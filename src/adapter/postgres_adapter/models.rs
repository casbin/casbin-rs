use super::schema::casbin_rules;

#[derive(Queryable, Identifiable)]
pub struct CasbinRule {
    pub id: i32,
    pub ptype: Option<String>,
    pub v0: Option<String>,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}

#[derive(Insertable)]
#[table_name = "casbin_rules"]
pub struct NewCasbinRule<'a> {
    pub ptype: Option<&'a str>,
    pub v0: Option<&'a str>,
    pub v1: Option<&'a str>,
    pub v2: Option<&'a str>,
    pub v3: Option<&'a str>,
    pub v4: Option<&'a str>,
    pub v5: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct ConnOptions<'a> {
    hostname: &'a str,
    port: u16,
    username: Option<&'a str>,
    password: Option<&'a str>,
    database: &'a str,
    table: &'a str,
    pool_size: u8,
}

impl<'a> Default for ConnOptions<'a> {
    fn default() -> Self {
        ConnOptions {
            hostname: "localhost",
            port: 5432,
            username: None,
            password: None,
            database: "casbin",
            table: "casbin_rules",
            pool_size: 8,
        }
    }
}

impl<'a> ConnOptions<'a> {
    pub fn set_hostname(&mut self, hostname: &'a str) -> &mut Self {
        self.hostname = hostname;
        self
    }

    pub fn set_port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    fn get_host(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }

    pub fn set_auth(&mut self, username: &'a str, password: &'a str) -> &mut Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    fn get_auth(&self) -> Option<String> {
        if let (Some(user), Some(pass)) = (self.username, self.password) {
            Some(format!("{}:{}", user, pass))
        } else {
            None
        }
    }

    pub fn get_url(&self) -> String {
        if let Some(auth) = self.get_auth() {
            format!("postgres://{}@{}/{}", auth, self.get_host(), self.database)
        } else {
            format!("postgres://{}/{}", self.get_host(), self.database)
        }
    }

    // fn set_table(&mut self, table: &'a str) -> &mut Self {
    //     self.table = table;
    //     self
    // }

    pub fn get_table(&self) -> String {
        self.table.to_owned()
    }

    pub fn set_pool(&mut self, pool_size: u8) -> &mut Self {
        self.pool_size = pool_size;
        self
    }

    pub fn get_db(&self) -> String {
        self.database.to_string()
    }
}
