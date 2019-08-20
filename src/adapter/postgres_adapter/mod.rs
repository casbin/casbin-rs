use crate::adapter::Adapter;
use crate::model::Model;

use diesel::{
    self,
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool, PoolError},
    result::Error,
    sql_query, BoolExpressionMethods, ExpressionMethods, PgExpressionMethods, QueryDsl,
    RunQueryDsl,
};

mod models;
mod schema;

use models::*;

pub struct PostgresAdapter {
    pool: Pool<ConnectionManager<PgConnection>>,
}

pub enum DieselError {
    PoolError(PoolError),
    Error(Error),
}

impl<'a> PostgresAdapter {
    pub fn new(conn_opts: ConnOptions) -> Result<Self, DieselError> {
        let manager = ConnectionManager::<PgConnection>::new(conn_opts.get_url());

        let pool = Pool::builder()
            .build(manager)
            .map_err(DieselError::PoolError)?;

        pool.get()
            .map_err(DieselError::PoolError)
            .and_then(|conn| {
                sql_query(format!(
                    r#"
                    SELECT 'CREATE DATABASE {}'
                        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{}')
                    "#,
                    conn_opts.get_db(),
                    conn_opts.get_db()
                ))
                .execute(&conn)
                .map(|_| conn)
                .map_err(DieselError::Error)
            })
            .and_then(|conn| {
                sql_query(format!(
                    r#"
                            CREATE TABLE IF NOT EXISTS {} (
                                id SERIAL PRIMARY KEY,
                                ptype VARCHAR,
                                v0 VARCHAR,
                                v1 VARCHAR,
                                v2 VARCHAR,
                                v3 VARCHAR,
                                v4 VARCHAR,
                                v5 VARCHAR
                            );
                        "#,
                    conn_opts.get_table()
                ))
                .execute(&conn)
                .map_err(DieselError::Error)
            })
            .map(|_x| Self { pool })
    }

    pub fn save_policy_line(&self, ptype: &'a str, rule: Vec<&'a str>) -> NewCasbinRule<'a> {
        let mut new_rule = NewCasbinRule {
            ptype: Some(ptype),
            v0: None,
            v1: None,
            v2: None,
            v3: None,
            v4: None,
            v5: None,
        };

        if !rule.is_empty() {
            new_rule.v0 = Some(rule[0]);
        }

        if rule.len() > 1 {
            new_rule.v1 = Some(rule[1]);
        }

        if rule.len() > 2 {
            new_rule.v2 = Some(rule[2]);
        }

        if rule.len() > 3 {
            new_rule.v3 = Some(rule[3]);
        }

        if rule.len() > 4 {
            new_rule.v4 = Some(rule[4]);
        }

        if rule.len() > 5 {
            new_rule.v5 = Some(rule[5]);
        }

        new_rule
    }

    pub fn load_policy_line(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        if let Some(ref sec) = casbin_rule.ptype {
            if sec.chars().nth(0).is_some() {
                return Some(
                    vec![
                        &casbin_rule.v0,
                        &casbin_rule.v1,
                        &casbin_rule.v2,
                        &casbin_rule.v3,
                        &casbin_rule.v4,
                        &casbin_rule.v5,
                    ]
                    .iter()
                    .filter_map(|x| x.as_ref())
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>(),
                );
            }
        }

        None
    }
}

impl Adapter for PostgresAdapter {
    fn load_policy(&self, m: &mut Model) {
        use schema::casbin_rules::dsl::casbin_rules;

        // Todo: add error handling to Adapter trait
        let _ = self
            .pool
            .get()
            .map_err(DieselError::PoolError)
            .and_then(|conn| {
                casbin_rules
                    .load::<CasbinRule>(&conn)
                    .map_err(DieselError::Error)
            })
            .and_then(move |rules| {
                for casbin_rule in rules.into_iter() {
                    let rule = self.load_policy_line(&casbin_rule);

                    if let Some(ref ptype) = casbin_rule.ptype {
                        let sec = ptype;
                        if let Some(t1) = m.model.get_mut(sec) {
                            if let Some(t2) = t1.get_mut(ptype) {
                                if let Some(rule) = rule {
                                    t2.policy.push(rule);
                                }
                            }
                        }
                    }
                }

                Ok(())
            });
    }

    fn save_policy(&self, m: &mut Model) {
        use schema::casbin_rules::dsl::casbin_rules;

        // Todo: add error handling to Adapter trait
        let _ = self
            .pool
            .get()
            .map_err(DieselError::PoolError)
            .and_then(|conn| {
                diesel::delete(casbin_rules)
                    .execute(&conn)
                    .map(move |_| conn)
                    .map_err(DieselError::Error)
            })
            .and_then(|conn| {
                if let Some(ast_map) = m.model.get("p") {
                    for (ref ptype, ref ast) in ast_map {
                        ast.policy.iter().for_each(|rule| {
                            let new_rule = self.save_policy_line(
                                ptype.as_str(),
                                rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                            );

                            let _ = diesel::insert_into(casbin_rules)
                                .values(&new_rule)
                                .execute(&conn)
                                .map_err(DieselError::Error);
                        });
                    }
                }

                if let Some(ast_map) = m.model.get("g") {
                    for (ref ptype, ref ast) in ast_map {
                        ast.policy.iter().for_each(|rule| {
                            let new_rule = self.save_policy_line(
                                ptype.as_str(),
                                rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                            );

                            let _ = diesel::insert_into(casbin_rules)
                                .values(&new_rule)
                                .execute(&conn)
                                .map_err(DieselError::Error);
                        });
                    }
                }

                Ok(())
            });
    }

    fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<&str>) -> bool {
        use schema::casbin_rules::dsl::casbin_rules;

        self.pool
            .get()
            .map_err(DieselError::PoolError)
            .and_then(move |conn| {
                let new_rule = self.save_policy_line(ptype, rule);

                diesel::insert_into(casbin_rules)
                    .values(&new_rule)
                    .execute(&conn)
                    .map_err(DieselError::Error)
            })
            .is_ok()
    }

    fn remove_policy(&self, _sec: &str, pt: &str, rule: Vec<&str>) -> bool {
        use schema::casbin_rules::dsl::*;

        self.pool
            .get()
            .map_err(DieselError::PoolError)
            .and_then(move |conn| {
                diesel::delete(
                    casbin_rules.filter(
                        ptype.eq(pt).and(
                            v0.is_not_distinct_from(rule.get(0)).and(
                                v1.is_not_distinct_from(rule.get(1))
                                    .and(v2.is_not_distinct_from(rule.get(2)))
                                    .and(
                                        v3.is_not_distinct_from(rule.get(3))
                                            .and(v4.is_not_distinct_from(rule.get(4)))
                                            .and(v5.is_not_distinct_from(rule.get(5))),
                                    ),
                            ),
                        ),
                    ),
                )
                .execute(&conn)
                .and_then(|n| if n == 1 { Ok(()) } else { Err(Error::NotFound) })
                .map_err(DieselError::Error)
            })
            .is_ok()
    }

    fn remove_filtered_policy(
        &self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        use schema::casbin_rules::dsl::*;

        if field_index <= 5 && !field_values.is_empty() && field_values.len() <= 6 - field_index {
            self.pool
                .get()
                .map_err(DieselError::PoolError)
                .and_then(|conn| {
                    if field_index == 0 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v0.is_not_distinct_from(field_values.get(0)).and(
                                        v1.is_not_distinct_from(field_values.get(1))
                                            .and(v2.is_not_distinct_from(field_values.get(2)))
                                            .and(
                                                v3.is_not_distinct_from(field_values.get(3))
                                                    .and(
                                                        v4.is_not_distinct_from(
                                                            field_values.get(4),
                                                        ),
                                                    )
                                                    .and(
                                                        v5.is_not_distinct_from(
                                                            field_values.get(5),
                                                        ),
                                                    ),
                                            ),
                                    ),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else if field_index == 1 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v1.is_not_distinct_from(field_values.get(0))
                                        .and(v2.is_not_distinct_from(field_values.get(1)))
                                        .and(
                                            v3.is_not_distinct_from(field_values.get(2))
                                                .and(v4.is_not_distinct_from(field_values.get(3)))
                                                .and(v5.is_not_distinct_from(field_values.get(4))),
                                        ),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else if field_index == 2 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v2.is_not_distinct_from(field_values.get(0))
                                        .and(v3.is_not_distinct_from(field_values.get(1)))
                                        .and(v4.is_not_distinct_from(field_values.get(2))),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else if field_index == 3 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v3.is_not_distinct_from(field_values.get(0))
                                        .and(v4.is_not_distinct_from(field_values.get(1)))
                                        .and(v5.is_not_distinct_from(field_values.get(2))),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else if field_index == 4 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype
                                    .eq(pt)
                                    .and(v4.is_not_distinct_from(field_values.get(0)))
                                    .and(v5.is_not_distinct_from(field_values.get(1))),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype
                                    .eq(pt)
                                    .and(v5.is_not_distinct_from(field_values.get(0))),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    }
                })
                .and_then(|n| {
                    if n == 1 {
                        Ok(())
                    } else {
                        Err(DieselError::Error(Error::NotFound))
                    }
                })
                .is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter() {
        use crate::adapter::FileAdapter;
        use crate::enforcer::Enforcer;
        use crate::model::Model;

        let mut m = Model::new();
        m.load_model("examples/rbac_model.conf");

        let mut conn_opts = ConnOptions::default();
        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let mut e = Enforcer::new(m, file_adapter);
        let adapter = PostgresAdapter::new(conn_opts);
        assert!(adapter.is_ok());

        if let Ok(mut adapter) = adapter {
            adapter.save_policy(&mut e.model);

            assert!(adapter.remove_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.remove_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(adapter.add_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.add_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.add_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.add_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.add_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(adapter.remove_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.remove_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(!adapter.remove_policy("", "g", vec!["alice", "data2_admin", "not_exists"]));

            assert!(adapter.add_policy("", "g", vec!["alice", "data2_admin"]));
            assert!(!adapter.remove_filtered_policy(
                "",
                "g",
                0,
                vec!["alice", "data2_admin", "not_exists"]
            ));
            assert!(adapter.remove_filtered_policy("", "g", 0, vec!["alice", "data2_admin"]));

            assert!(adapter.add_policy(
                "",
                "g",
                vec!["alice", "data2_admin", "domain1", "domain2"]
            ));
            assert!(adapter.remove_filtered_policy(
                "",
                "g",
                1,
                vec!["data2_admin", "domain1", "domain2"]
            ));
        }
    }
}
