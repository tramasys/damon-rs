use super::{
    Duration, Error, MAX_EAGER_READ_CAPACITY, Path, QuotaConfig, QuotaGoal, QuotaGoalConfig,
    QuotaGoalMetric, QuotaGoalTuner, QuotaWeights, Result, SchemeQuotas, ensure_count,
    exact_millis, needs_stage, optional_read, path_exists, read_enum, read_i32, read_sysfs_string,
    read_u32, read_u64, read_usize, stage_optional_default, validate_count, validate_sysfs_string,
    write_bytes, write_enum, write_value,
};

impl SchemeQuotas {
    pub(crate) fn validate_goals(goals: &[QuotaGoalConfig]) -> Result<()> {
        validate_count("quota goal count", goals.len())?;
        for goal in goals {
            goal.validate()?;
        }
        Ok(())
    }

    /// Returns this quota directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the time quota.
    pub fn time(&self) -> Result<Duration> {
        Ok(Duration::from_millis(read_u64(&self.path.join("ms"))?))
    }

    /// Sets the time quota.
    pub fn set_time(&self, value: Duration) -> Result<()> {
        write_value(&self.path.join("ms"), exact_millis("quota time", value)?)
    }

    /// Reads the size quota in DAMON core address units.
    pub fn size_units(&self) -> Result<u64> {
        read_u64(&self.path.join("bytes"))
    }

    /// Sets the size quota in DAMON core address units.
    pub fn set_size_units(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("bytes"), value)
    }

    /// Reads the quota reset interval.
    pub fn reset_interval(&self) -> Result<Duration> {
        Ok(Duration::from_millis(read_u64(
            &self.path.join("reset_interval_ms"),
        )?))
    }

    /// Sets the quota reset interval.
    pub fn set_reset_interval(&self, value: Duration) -> Result<()> {
        write_value(
            &self.path.join("reset_interval_ms"),
            exact_millis("quota reset interval", value)?,
        )
    }

    /// Reads the effective size quota in DAMON core address units.
    pub fn effective_size_units(&self) -> Result<u64> {
        read_u64(&self.path.join("effective_bytes"))
    }

    /// Reads the quota prioritization weights.
    pub fn weights(&self) -> Result<QuotaWeights> {
        let path = self.path.join("weights");
        Ok(QuotaWeights {
            size_per_thousand: read_u32(&path.join("sz_permil"))?,
            accesses_per_thousand: read_u32(&path.join("nr_accesses_permil"))?,
            age_per_thousand: read_u32(&path.join("age_permil"))?,
        })
    }

    /// Writes the quota prioritization weights.
    pub fn set_weights(&self, weights: QuotaWeights) -> Result<()> {
        let path = self.path.join("weights");
        write_value(&path.join("sz_permil"), weights.size_per_thousand)?;
        write_value(
            &path.join("nr_accesses_permil"),
            weights.accesses_per_thousand,
        )?;
        write_value(&path.join("age_permil"), weights.age_per_thousand)
    }

    /// Reads the quota-goal tuner.
    pub fn goal_tuner(&self) -> Result<QuotaGoalTuner> {
        read_enum(&self.path.join("goal_tuner"), QuotaGoalTuner::parse)
    }

    /// Selects the quota-goal tuner.
    pub fn set_goal_tuner(&self, tuner: &QuotaGoalTuner) -> Result<()> {
        write_enum(&self.path.join("goal_tuner"), tuner)
    }

    /// Reads the failed-application charge numerator.
    pub fn failure_charge_numerator(&self) -> Result<u32> {
        read_u32(&self.path.join("fail_charge_num"))
    }

    /// Sets the failed-application charge numerator.
    pub fn set_failure_charge_numerator(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("fail_charge_num"), value)
    }

    /// Reads the failed-application charge denominator.
    pub fn failure_charge_denominator(&self) -> Result<u32> {
        read_u32(&self.path.join("fail_charge_denom"))
    }

    /// Sets the failed-application charge denominator.
    pub fn set_failure_charge_denominator(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("fail_charge_denom"), value)
    }

    /// Reads the number of staged quota goals.
    pub fn goal_count(&self) -> Result<usize> {
        read_usize(&self.path.join("goals/nr_goals"))
    }

    /// Reconstructs the staged quota-goal directories.
    pub fn set_goal_count(&self, count: usize) -> Result<()> {
        validate_count("quota goal count", count)?;
        write_value(&self.path.join("goals/nr_goals"), count)
    }

    /// Returns a typed handle for one staged quota goal.
    #[must_use]
    pub fn goal(&self, index: usize) -> QuotaGoal {
        QuotaGoal {
            path: self.path.join("goals").join(index.to_string()),
        }
    }

    /// Reads the owned quota configuration.
    pub fn configuration(&self) -> Result<QuotaConfig> {
        Ok(QuotaConfig {
            time: self.time()?,
            size_units: self.size_units()?,
            reset_interval: self.reset_interval()?,
            weights: self.weights()?,
            goals: self.goal_configurations()?,
            goal_tuner: optional_read(&self.path.join("goal_tuner"), || self.goal_tuner())?
                .unwrap_or_default(),
            failure_charge_numerator: optional_read(&self.path.join("fail_charge_num"), || {
                self.failure_charge_numerator()
            })?
            .unwrap_or(0),
            failure_charge_denominator: optional_read(
                &self.path.join("fail_charge_denom"),
                || self.failure_charge_denominator(),
            )?
            .unwrap_or(0),
        })
    }

    pub(crate) fn goal_configurations(&self) -> Result<Vec<QuotaGoalConfig>> {
        let goals_path = self.path.join("goals/nr_goals");
        if !path_exists(&goals_path)? {
            return Ok(Vec::new());
        }
        let count = self.goal_count()?;
        let mut values = Vec::with_capacity(count.min(MAX_EAGER_READ_CAPACITY));
        for index in 0..count {
            values.push(self.goal(index).configuration()?);
        }
        Ok(values)
    }

    pub(crate) fn stage_goals_from(
        &self,
        goals: &[QuotaGoalConfig],
        observed: Option<&[QuotaGoalConfig]>,
    ) -> Result<()> {
        Self::validate_goals(goals)?;
        if observed == Some(goals) {
            return Ok(());
        }
        let goals_path = self.path.join("goals/nr_goals");
        if !path_exists(&goals_path)? {
            return if goals.is_empty() {
                Ok(())
            } else {
                Err(Error::UnsupportedFeature {
                    feature: "DAMOS quota goals",
                })
            };
        }
        ensure_count(&goals_path, goals.len())?;
        let comparable = observed.filter(|values| values.len() == goals.len());
        for (index, goal) in goals.iter().enumerate() {
            if comparable.is_none_or(|values| &values[index] != goal) {
                self.goal(index).stage_configuration(goal)?;
            }
        }
        Ok(())
    }

    pub(in crate::sysfs::configuration) fn stage_configuration_from(
        &self,
        config: &QuotaConfig,
        observed: Option<&QuotaConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.time), &config.time) {
            self.set_time(config.time)?;
        }
        if needs_stage(observed.map(|value| &value.size_units), &config.size_units) {
            self.set_size_units(config.size_units)?;
        }
        if needs_stage(
            observed.map(|value| &value.reset_interval),
            &config.reset_interval,
        ) {
            self.set_reset_interval(config.reset_interval)?;
        }
        if needs_stage(observed.map(|value| &value.weights), &config.weights) {
            self.set_weights(config.weights)?;
        }
        if needs_stage(observed.map(|value| &value.goals), &config.goals) {
            self.stage_goals_from(&config.goals, observed.map(|value| value.goals.as_slice()))?;
        }
        if needs_stage(observed.map(|value| &value.goal_tuner), &config.goal_tuner) {
            stage_optional_default(
                &self.path.join("goal_tuner"),
                &config.goal_tuner,
                &QuotaGoalTuner::default(),
                "DAMOS quota goal tuner",
                || self.set_goal_tuner(&config.goal_tuner),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.failure_charge_numerator),
            &config.failure_charge_numerator,
        ) {
            stage_optional_default(
                &self.path.join("fail_charge_num"),
                &config.failure_charge_numerator,
                &0,
                "DAMOS failure charge ratio",
                || self.set_failure_charge_numerator(config.failure_charge_numerator),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.failure_charge_denominator),
            &config.failure_charge_denominator,
        ) {
            stage_optional_default(
                &self.path.join("fail_charge_denom"),
                &config.failure_charge_denominator,
                &0,
                "DAMOS failure charge ratio",
                || self.set_failure_charge_denominator(config.failure_charge_denominator),
            )?;
        }
        Ok(())
    }
}

impl QuotaGoal {
    /// Returns this quota goal's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the target metric.
    pub fn metric(&self) -> Result<QuotaGoalMetric> {
        read_enum(&self.path.join("target_metric"), QuotaGoalMetric::parse)
    }

    /// Sets the target metric.
    pub fn set_metric(&self, metric: &QuotaGoalMetric) -> Result<()> {
        write_enum(&self.path.join("target_metric"), metric)
    }

    /// Reads the target value in the metric's kernel-defined unit.
    pub fn target_value(&self) -> Result<u64> {
        read_u64(&self.path.join("target_value"))
    }

    /// Sets the target value in the metric's kernel-defined unit.
    pub fn set_target_value(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("target_value"), value)
    }

    /// Reads the userspace-fed current value.
    pub fn current_value(&self) -> Result<u64> {
        read_u64(&self.path.join("current_value"))
    }

    /// Sets the userspace-fed current value.
    pub fn set_current_value(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("current_value"), value)
    }

    /// Reads the NUMA node identifier.
    pub fn node_id(&self) -> Result<i32> {
        read_i32(&self.path.join("nid"))
    }

    /// Sets the NUMA node identifier.
    pub fn set_node_id(&self, value: i32) -> Result<()> {
        write_value(&self.path.join("nid"), value)
    }

    /// Reads the memory-control-group path.
    pub fn cgroup_path(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("path"))
    }

    /// Sets the memory-control-group path.
    pub fn set_cgroup_path(&self, value: &str) -> Result<()> {
        validate_sysfs_string("quota goal cgroup path", value)?;
        write_bytes(&self.path.join("path"), value.as_bytes())
    }

    /// Reads this quota goal as owned data.
    pub fn configuration(&self) -> Result<QuotaGoalConfig> {
        let metric = optional_read(&self.path.join("target_metric"), || self.metric())?
            .unwrap_or(QuotaGoalMetric::UserInput);
        let node_id = if metric.requires_node() || matches!(metric, QuotaGoalMetric::Unknown(_)) {
            Some(self.node_id()?)
        } else {
            None
        };
        let cgroup_path =
            if metric.requires_cgroup_path() || matches!(metric, QuotaGoalMetric::Unknown(_)) {
                Some(self.cgroup_path()?)
            } else {
                None
            };
        Ok(QuotaGoalConfig {
            metric,
            target_value: self.target_value()?,
            current_value: self.current_value()?,
            node_id,
            cgroup_path,
        })
    }

    pub(super) fn stage_configuration(&self, config: &QuotaGoalConfig) -> Result<()> {
        if path_exists(&self.path.join("target_metric"))? {
            self.set_metric(&config.metric)?;
        } else if config.metric != QuotaGoalMetric::UserInput {
            return Err(Error::UnsupportedFeature {
                feature: "DAMOS quota goal metrics",
            });
        }
        self.set_target_value(config.target_value)?;
        self.set_current_value(config.current_value)?;
        if let Some(node_id) = config.node_id {
            self.set_node_id(node_id)?;
        }
        if let Some(path) = &config.cgroup_path {
            self.set_cgroup_path(path)?;
        }
        Ok(())
    }
}
