use super::{
    Duration, Path, Result, SchemeWatermarks, WatermarkMetric, WatermarksConfig, exact_micros,
    needs_stage, read_enum, read_u64, write_enum, write_value,
};

impl SchemeWatermarks {
    /// Returns this watermarks directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the watermark metric.
    pub fn metric(&self) -> Result<WatermarkMetric> {
        read_enum(&self.path.join("metric"), WatermarkMetric::parse)
    }

    /// Selects the watermark metric.
    pub fn set_metric(&self, metric: &WatermarkMetric) -> Result<()> {
        write_enum(&self.path.join("metric"), metric)
    }

    /// Reads the watermark check interval.
    pub fn interval(&self) -> Result<Duration> {
        Ok(Duration::from_micros(read_u64(
            &self.path.join("interval_us"),
        )?))
    }

    /// Sets the watermark check interval.
    pub fn set_interval(&self, value: Duration) -> Result<()> {
        write_value(
            &self.path.join("interval_us"),
            exact_micros("watermark interval", value)?,
        )
    }

    /// Reads the high watermark.
    pub fn high(&self) -> Result<u64> {
        read_u64(&self.path.join("high"))
    }

    /// Sets the high watermark.
    pub fn set_high(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("high"), value)
    }

    /// Reads the middle watermark.
    pub fn middle(&self) -> Result<u64> {
        read_u64(&self.path.join("mid"))
    }

    /// Sets the middle watermark.
    pub fn set_middle(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("mid"), value)
    }

    /// Reads the low watermark.
    pub fn low(&self) -> Result<u64> {
        read_u64(&self.path.join("low"))
    }

    /// Sets the low watermark.
    pub fn set_low(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("low"), value)
    }

    /// Reads all watermark settings.
    pub fn configuration(&self) -> Result<WatermarksConfig> {
        Ok(WatermarksConfig {
            metric: self.metric()?,
            interval: self.interval()?,
            high: self.high()?,
            middle: self.middle()?,
            low: self.low()?,
        })
    }

    pub(in crate::sysfs::configuration) fn stage_configuration_from(
        &self,
        config: &WatermarksConfig,
        observed: Option<&WatermarksConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.metric), &config.metric) {
            self.set_metric(&config.metric)?;
        }
        if needs_stage(observed.map(|value| &value.interval), &config.interval) {
            self.set_interval(config.interval)?;
        }
        if needs_stage(observed.map(|value| &value.high), &config.high) {
            self.set_high(config.high)?;
        }
        if needs_stage(observed.map(|value| &value.middle), &config.middle) {
            self.set_middle(config.middle)?;
        }
        if needs_stage(observed.map(|value| &value.low), &config.low) {
            self.set_low(config.low)?;
        }
        Ok(())
    }
}
