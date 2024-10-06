pub struct StringAdapter {
    policy_string: String,
    is_filtered: bool,
}

impl StringAdapter {
    pub fn new(policy_string: String) -> Self {
        StringAdapter {
            policy_string,
            is_filtered: false,
        }
    }

    pub fn new_filtered_adapter(policy_string: String) -> Self {
        StringAdapter {
            policy_string,
            is_filtered: true,
        }
    }

    fn load_policy_from_string(
        &mut self,
        m: &mut dyn Model,
        handler: LoadPolicyFileHandler,
    ) -> Result<()> {
        let lines = self.policy_string.lines();
        for line in lines {
            handler(line.to_string(), m);
        }
        Ok(())
    }

    fn load_filtered_policy_from_string<'a>(
        &mut self,
        m: &mut dyn Model,
        filter: Filter<'a>,
        handler: LoadFilteredPolicyFileHandler<'a>,
    ) -> Result<bool> {
        let mut is_filtered = false;
        let lines = self.policy_string.lines();
        for line in lines {
            if handler(line.to_string(), m, &filter) {
                is_filtered = true;
            }
        }
        Ok(is_filtered)
    }

    fn save_policy_to_string(&mut self, policies: String) -> Result<()> {
        self.policy_string = policies;
        Ok(())
    }
}

#[async_trait]
impl Adapter for StringAdapter {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        self.is_filtered = false;
        self.load_policy_from_string(m, load_policy_line)?;
        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<()> {
        self.is_filtered = self.load_filtered_policy_from_string(
            m,
            f,
            load_filtered_policy_line,
        )?;
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut policies = String::new();
        let ast_map = m.get_model().get("p").ok_or_else(|| {
            ModelError::P("Missing policy definition in conf file".to_owned())
        })?;

        for (ptype, ast) in ast_map {
            for rule in ast.get_policy() {
                writeln!(policies, "{},{}", ptype, rule.join(","))
                    .map_err(|e| AdapterError(e.into()))?;
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                for rule in ast.get_policy() {
                    writeln!(policies, "{},{}", ptype, rule.join(","))
                        .map_err(|e| AdapterError(e.into()))?;
                }
            }
        }

        self.save_policy_to_string(policies)?;
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.save_policy_to_string(String::new())?;
        Ok(())
    }

    async fn add_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        Ok(true)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}
