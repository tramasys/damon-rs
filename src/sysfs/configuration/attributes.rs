//! Typed handles for nested DAMON sysfs attributes.

use super::{
    ByteSizeRange, DestinationConfig, Duration, Error, FilterConfig, InitialRegionConfig,
    MAX_EAGER_READ_CAPACITY, OperationAttributesConfig, Path, PathBuf, ProbePreparationAction,
    ProbePreparationConfig, QuotaConfig, QuotaGoalConfig, QuotaGoalMetric, QuotaGoalTuner,
    QuotaWeights, Result, SampleControlConfig, SampleFilterConfig, SampleFilterType,
    SamplePrimitivesConfig, SchemeFilterType, WatermarkMetric, WatermarksConfig, ensure_count,
    exact_micros, exact_millis, invalid_kernel_value, needs_stage, optional_pair, optional_read,
    path_exists, read_bool, read_enum, read_i32, read_indexed, read_sysfs_string, read_u32,
    read_u64, read_usize, stage_optional_default, validate_count, validate_sysfs_string,
    write_bool, write_bytes, write_enum, write_value,
};

mod filter;
mod quota;
mod watermark;

/// Runtime counters reported by a DAMOS scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SchemeStats {
    /// Number of regions for which application was attempted.
    pub regions_tried: u64,
    /// Attempted size in DAMON core address units.
    pub size_tried_units: u64,
    /// Number of successful applications.
    pub regions_applied: u64,
    /// Successfully applied size in DAMON core address units.
    pub size_applied_units: u64,
    /// Size passed by operations-layer filters in core address units, when exposed.
    pub operations_filter_passed_units: Option<u64>,
    /// Number of quota limit exceedances.
    pub quota_exceeds: u64,
    /// Number of snapshots represented by the counters, when exposed.
    pub snapshots: Option<u64>,
    /// Configured maximum number of snapshots, when exposed.
    pub maximum_snapshots: Option<u64>,
}

/// A typed handle to one staged initial region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialRegion {
    pub(super) path: PathBuf,
}

/// A typed handle to one staged DAMOS quota directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeQuotas {
    pub(super) path: PathBuf,
}

/// A typed handle to one staged DAMOS quota goal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaGoal {
    pub(super) path: PathBuf,
}

/// A typed handle to one staged DAMOS watermarks directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeWatermarks {
    pub(super) path: PathBuf,
}

/// A typed handle to one staged DAMOS filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeFilter {
    pub(super) path: PathBuf,
}

/// A typed handle to one staged weighted migration destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationDestination {
    pub(super) path: PathBuf,
}

/// A typed handle to operation-specific monitoring attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAttributes {
    pub(super) path: PathBuf,
}

/// A typed handle to one monitoring-probe preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbePreparation {
    pub(super) path: PathBuf,
}

/// A typed handle to access-sample controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleControl {
    pub(super) path: PathBuf,
}

/// A typed handle to one access-sample filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleFilter {
    pub(super) path: PathBuf,
}

impl InitialRegion {
    /// Returns this initial region's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the region's inclusive start address in core address units.
    pub fn start(&self) -> Result<u64> {
        read_u64(&self.path.join("start"))
    }

    /// Writes the region's inclusive start address in core address units.
    pub fn set_start(&self, start: u64) -> Result<()> {
        write_value(&self.path.join("start"), start)
    }

    /// Reads the region's exclusive end address in core address units.
    pub fn end(&self) -> Result<u64> {
        read_u64(&self.path.join("end"))
    }

    /// Writes the region's exclusive end address in core address units.
    pub fn set_end(&self, end: u64) -> Result<()> {
        write_value(&self.path.join("end"), end)
    }

    /// Reads both boundaries as an owned configuration value.
    pub fn configuration(&self) -> Result<InitialRegionConfig> {
        Ok(InitialRegionConfig {
            start: self.start()?,
            end: self.end()?,
        })
    }

    /// Writes both region boundaries.
    pub fn stage_configuration(&self, config: InitialRegionConfig) -> Result<()> {
        InitialRegionConfig::new(config.start, config.end)?;
        self.set_start(config.start)?;
        self.set_end(config.end)
    }
}

impl OperationAttributes {
    /// Returns this attributes directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads whether external access reports are consumed.
    pub fn use_reports(&self) -> Result<bool> {
        read_bool(&self.path.join("use_reports"))
    }

    /// Sets whether external access reports are consumed.
    pub fn set_use_reports(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("use_reports"), value)
    }

    /// Reads whether monitoring is write-only.
    pub fn write_only(&self) -> Result<bool> {
        read_bool(&self.path.join("write_only"))
    }

    /// Sets whether monitoring is write-only.
    pub fn set_write_only(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("write_only"), value)
    }

    /// Reads the kernel CPU-list string.
    pub fn cpus(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("cpus"))
    }

    /// Writes the kernel CPU-list string.
    pub fn set_cpus(&self, value: &str) -> Result<()> {
        validate_sysfs_string("operation CPU list", value)?;
        write_bytes(&self.path.join("cpus"), value.as_bytes())
    }

    /// Reads the kernel thread-list string.
    pub fn thread_ids(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("tids"))
    }

    /// Writes the kernel thread-list string.
    pub fn set_thread_ids(&self, value: &str) -> Result<()> {
        validate_sysfs_string("operation thread list", value)?;
        write_bytes(&self.path.join("tids"), value.as_bytes())
    }

    /// Reads all operation-specific attributes.
    pub fn configuration(&self) -> Result<OperationAttributesConfig> {
        Ok(OperationAttributesConfig {
            use_reports: self.use_reports()?,
            write_only: self.write_only()?,
            cpus: self.cpus()?,
            thread_ids: self.thread_ids()?,
        })
    }

    pub(super) fn stage_configuration(&self, config: &OperationAttributesConfig) -> Result<()> {
        self.set_use_reports(config.use_reports)?;
        self.set_write_only(config.write_only)?;
        self.set_cpus(&config.cpus)?;
        self.set_thread_ids(&config.thread_ids)
    }
}

impl ProbePreparation {
    /// Returns this preparation's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the preparation action.
    pub fn action(&self) -> Result<ProbePreparationAction> {
        read_enum(
            &self.path.join("prep_action"),
            ProbePreparationAction::parse,
        )
    }

    /// Writes the preparation action.
    pub fn set_action(&self, action: &ProbePreparationAction) -> Result<()> {
        write_enum(&self.path.join("prep_action"), action)
    }

    /// Reads this preparation into owned data.
    pub fn configuration(&self) -> Result<ProbePreparationConfig> {
        Ok(ProbePreparationConfig::new(self.action()?))
    }

    pub(super) fn stage_configuration(&self, config: &ProbePreparationConfig) -> Result<()> {
        self.set_action(&config.action)
    }
}

impl SampleControl {
    /// Returns this sample-control directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads whether page-table sampling is enabled.
    pub fn page_table_enabled(&self) -> Result<bool> {
        read_bool(&self.path.join("primitives/page_table"))
    }

    /// Enables or disables page-table sampling.
    pub fn set_page_table_enabled(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("primitives/page_table"), value)
    }

    /// Reads whether page-fault sampling is enabled.
    pub fn page_fault_enabled(&self) -> Result<bool> {
        read_bool(&self.path.join("primitives/page_fault"))
    }

    /// Enables or disables page-fault sampling.
    pub fn set_page_fault_enabled(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("primitives/page_fault"), value)
    }

    /// Reads the number of staged sample filters.
    pub fn filter_count(&self) -> Result<usize> {
        read_usize(&self.path.join("filters/nr_filters"))
    }

    /// Reconstructs the staged sample-filter directories.
    pub fn set_filter_count(&self, count: usize) -> Result<()> {
        validate_count("sample filter count", count)?;
        write_value(&self.path.join("filters/nr_filters"), count)
    }

    /// Returns a typed handle to one sample filter.
    #[must_use]
    pub fn filter(&self, index: usize) -> SampleFilter {
        SampleFilter {
            path: self.path.join("filters").join(index.to_string()),
        }
    }

    /// Reads the complete sample-control configuration.
    pub fn configuration(&self) -> Result<SampleControlConfig> {
        Ok(SampleControlConfig {
            primitives: SamplePrimitivesConfig {
                page_table: self.page_table_enabled()?,
                page_fault: self.page_fault_enabled()?,
            },
            filters: read_indexed(self.filter_count()?, |index| {
                self.filter(index).configuration()
            })?,
        })
    }

    pub(super) fn stage_configuration(&self, config: &SampleControlConfig) -> Result<()> {
        self.set_page_table_enabled(config.primitives.page_table)?;
        self.set_page_fault_enabled(config.primitives.page_fault)?;
        ensure_count(&self.path.join("filters/nr_filters"), config.filters.len())?;
        for (index, filter) in config.filters.iter().enumerate() {
            self.filter(index).stage_configuration(filter)?;
        }
        Ok(())
    }
}

impl SampleFilter {
    /// Returns this filter's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the filter type.
    pub fn filter_type(&self) -> Result<SampleFilterType> {
        read_enum(&self.path.join("type"), SampleFilterType::parse)
    }

    /// Sets the filter type.
    pub fn set_filter_type(&self, value: &SampleFilterType) -> Result<()> {
        write_enum(&self.path.join("type"), value)
    }

    /// Reads whether the filter matches its criterion.
    pub fn matching(&self) -> Result<bool> {
        read_bool(&self.path.join("matching"))
    }

    /// Sets whether the filter matches its criterion.
    pub fn set_matching(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("matching"), value)
    }

    /// Reads whether matching samples are allowed.
    pub fn allowed(&self) -> Result<bool> {
        read_bool(&self.path.join("allow"))
    }

    /// Sets whether matching samples are allowed.
    pub fn set_allowed(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("allow"), value)
    }

    /// Reads the kernel cpumask string.
    pub fn cpu_mask(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("cpumask"))
    }

    /// Writes the kernel cpumask string.
    pub fn set_cpu_mask(&self, value: &str) -> Result<()> {
        validate_sysfs_string("sample filter CPU mask", value)?;
        write_bytes(&self.path.join("cpumask"), value.as_bytes())
    }

    /// Reads the kernel thread-list string.
    pub fn thread_ids(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("tid_arr"))
    }

    /// Writes the kernel thread-list string.
    pub fn set_thread_ids(&self, value: &str) -> Result<()> {
        validate_sysfs_string("sample filter thread list", value)?;
        write_bytes(&self.path.join("tid_arr"), value.as_bytes())
    }

    /// Reads this sample filter into owned data.
    pub fn configuration(&self) -> Result<SampleFilterConfig> {
        let filter_type = self.filter_type()?;
        let mut config =
            SampleFilterConfig::new(filter_type.clone(), self.matching()?, self.allowed()?);
        match filter_type {
            SampleFilterType::CpuMask => config.cpu_mask = Some(self.cpu_mask()?),
            SampleFilterType::Threads => config.thread_ids = Some(self.thread_ids()?),
            SampleFilterType::Unknown(_) => {
                config.cpu_mask = optional_read(&self.path.join("cpumask"), || self.cpu_mask())?;
                config.thread_ids =
                    optional_read(&self.path.join("tid_arr"), || self.thread_ids())?;
            }
            SampleFilterType::Write => {}
        }
        Ok(config)
    }

    pub(super) fn stage_configuration(&self, config: &SampleFilterConfig) -> Result<()> {
        self.set_filter_type(&config.filter_type)?;
        self.set_matching(config.matching)?;
        self.set_allowed(config.allow)?;
        if let Some(value) = &config.cpu_mask {
            self.set_cpu_mask(value)?;
        }
        if let Some(value) = &config.thread_ids {
            self.set_thread_ids(value)?;
        }
        Ok(())
    }
}
