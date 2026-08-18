use super::{
    ByteSizeRange, DestinationConfig, Error, FilterConfig, MigrationDestination, Path, PathBuf,
    Result, SchemeFilter, SchemeFilterType, invalid_kernel_value, optional_pair, optional_read,
    path_exists, read_bool, read_enum, read_i32, read_sysfs_string, read_u32, read_u64,
    validate_count, validate_sysfs_string, write_bool, write_bytes, write_enum, write_value,
};

impl SchemeFilter {
    /// Returns this filter's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the filter type.
    pub fn filter_type(&self) -> Result<SchemeFilterType> {
        read_enum(&self.path.join("type"), SchemeFilterType::parse)
    }

    /// Sets the filter type.
    pub fn set_filter_type(&self, value: &SchemeFilterType) -> Result<()> {
        write_enum(&self.path.join("type"), value)
    }

    /// Reads whether the filter selects matching memory.
    pub fn matching(&self) -> Result<bool> {
        read_bool(&self.path.join("matching"))
    }

    /// Selects matching or non-matching memory.
    pub fn set_matching(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("matching"), value)
    }

    /// Reads whether selected memory is allowed through the filter.
    ///
    /// Kernels before Linux 6.14 expose no `allow` attribute and always reject
    /// memory selected by a filter.  Such filters are therefore reported as
    /// not allowing selected memory.
    pub fn allowed(&self) -> Result<bool> {
        self.allow_path()?
            .map_or(Ok(false), |path| read_bool(&path))
    }

    /// Sets whether selected memory is allowed through the filter.
    ///
    /// Setting `false` is a no-op on kernels whose filters have the original
    /// reject-only behavior.  Setting `true` requires the newer control.
    pub fn set_allowed(&self, value: bool) -> Result<()> {
        match self.allow_path()? {
            Some(path) => write_bool(&path, value),
            None if !value => Ok(()),
            None => Err(Error::UnsupportedFeature {
                feature: "DAMOS filter allow control",
            }),
        }
    }

    /// Reads the memory-control-group path.
    pub fn cgroup_path(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("memcg_path"))
    }

    /// Sets the memory-control-group path.
    pub fn set_cgroup_path(&self, value: &str) -> Result<()> {
        validate_sysfs_string("scheme filter cgroup path", value)?;
        write_bytes(&self.path.join("memcg_path"), value.as_bytes())
    }

    /// Reads the address-filter start in core address units.
    pub fn address_start(&self) -> Result<u64> {
        read_u64(&self.path.join("addr_start"))
    }

    /// Sets the address-filter start in core address units.
    pub fn set_address_start(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("addr_start"), value)
    }

    /// Reads the address-filter end in core address units.
    pub fn address_end(&self) -> Result<u64> {
        read_u64(&self.path.join("addr_end"))
    }

    /// Sets the address-filter end in core address units.
    pub fn set_address_end(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("addr_end"), value)
    }

    /// Reads the minimum huge-page size in bytes.
    pub fn minimum_size_bytes(&self) -> Result<u64> {
        read_u64(&self.path.join("min"))
    }

    /// Sets the minimum huge-page size in bytes.
    pub fn set_minimum_size_bytes(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("min"), value)
    }

    /// Reads the maximum huge-page size in bytes.
    pub fn maximum_size_bytes(&self) -> Result<u64> {
        read_u64(&self.path.join("max"))
    }

    /// Sets the maximum huge-page size in bytes.
    pub fn set_maximum_size_bytes(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("max"), value)
    }

    /// Reads the filtered DAMON target index.
    pub fn target_index(&self) -> Result<usize> {
        let path = self.path.join("damon_target_idx");
        let value = read_i32(&path)?;
        usize::try_from(value).map_err(|_| {
            invalid_kernel_value(&path, value.to_string(), "a non-negative target index")
        })
    }

    /// Sets the filtered DAMON target index.
    pub fn set_target_index(&self, value: usize) -> Result<()> {
        validate_count("target filter index", value)?;
        write_value(&self.path.join("damon_target_idx"), value)
    }

    /// Reads this filter as owned data.
    pub fn configuration(&self) -> Result<FilterConfig> {
        let filter_type = self.filter_type()?;
        let mut config = FilterConfig::new(filter_type.clone(), self.matching()?, self.allowed()?);
        match filter_type {
            SchemeFilterType::MemoryControlGroup => {
                config.cgroup_path = Some(self.cgroup_path()?);
            }
            SchemeFilterType::Address => {
                config.address_range = Some((self.address_start()?, self.address_end()?));
            }
            SchemeFilterType::HugePageSize => {
                config.size_range = Some(ByteSizeRange::new(
                    self.minimum_size_bytes()?,
                    self.maximum_size_bytes()?,
                )?);
            }
            SchemeFilterType::Target => {
                config.target_index = Some(self.target_index()?);
            }
            SchemeFilterType::Unknown(_) => {
                config.cgroup_path =
                    optional_read(&self.path.join("memcg_path"), || self.cgroup_path())?;
                config.address_range = optional_pair(
                    &self.path.join("addr_start"),
                    &self.path.join("addr_end"),
                    || Ok((self.address_start()?, self.address_end()?)),
                )?;
                config.size_range =
                    optional_pair(&self.path.join("min"), &self.path.join("max"), || {
                        ByteSizeRange::new(self.minimum_size_bytes()?, self.maximum_size_bytes()?)
                    })?;
                config.target_index =
                    optional_read(&self.path.join("damon_target_idx"), || self.target_index())?;
            }
            _ => {}
        }
        Ok(config)
    }

    pub(in crate::sysfs::configuration) fn stage_configuration(
        &self,
        config: &FilterConfig,
    ) -> Result<()> {
        self.set_filter_type(&config.filter_type)?;
        self.set_matching(config.matching)?;
        self.set_allowed(config.allow)?;
        if let Some(path) = &config.cgroup_path {
            self.set_cgroup_path(path)?;
        }
        if let Some((start, end)) = config.address_range {
            self.set_address_start(start)?;
            self.set_address_end(end)?;
        }
        if let Some(range) = config.size_range {
            self.set_minimum_size_bytes(range.min())?;
            self.set_maximum_size_bytes(range.max())?;
        }
        if let Some(index) = config.target_index {
            self.set_target_index(index)?;
        }
        Ok(())
    }

    pub(super) fn allow_path(&self) -> Result<Option<PathBuf>> {
        for name in ["allow", "pass"] {
            let path = self.path.join(name);
            if path_exists(&path)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}

impl MigrationDestination {
    /// Returns this migration destination's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the NUMA node identifier.
    pub fn node_id(&self) -> Result<u32> {
        read_u32(&self.path.join("id"))
    }

    /// Sets the NUMA node identifier.
    pub fn set_node_id(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("id"), value)
    }

    /// Reads the relative destination weight.
    pub fn weight(&self) -> Result<u32> {
        read_u32(&self.path.join("weight"))
    }

    /// Sets the relative destination weight.
    pub fn set_weight(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("weight"), value)
    }

    /// Reads both destination attributes.
    pub fn configuration(&self) -> Result<DestinationConfig> {
        Ok(DestinationConfig {
            node_id: self.node_id()?,
            weight: self.weight()?,
        })
    }

    pub(in crate::sysfs::configuration) fn stage_configuration(
        &self,
        config: DestinationConfig,
    ) -> Result<()> {
        self.set_node_id(config.node_id)?;
        self.set_weight(config.weight)
    }
}
