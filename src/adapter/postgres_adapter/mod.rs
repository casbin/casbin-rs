use crate::adapter::Adapter;
use crate::model::Model;

use diesel::{
    self,
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool, PoolError},
    result::Error,
    sql_query, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
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
                    CREATE TABLE IF NOT EXISTS {} (
                        id SERIAL PRIMARY KEY,
                        ptype VARCHAR,
                        v0 VARCHAR,
                        v1 VARCHAR,
                        v2 VARCHAR,
                        v3 VARCHAR,
                        v4 VARCHAR,
                        v5 VARCHAR
                    )
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
            if let Some(_) = sec.chars().nth(0) {
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

        self.pool
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

        self.pool
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

                            diesel::insert_into(casbin_rules)
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

                            diesel::insert_into(casbin_rules)
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

    fn remove_policy(&self, sec: &str, pt: &str, rule: Vec<&str>) -> bool {
        use schema::casbin_rules::dsl::*;

        self.pool
            .get()
            .map_err(DieselError::PoolError)
            .and_then(move |conn| {
                diesel::delete(
                    casbin_rules.filter(
                        ptype.eq(pt).and(
                            v0.eq(rule.get(0)).and(
                                v1.eq(rule.get(1)).and(v2.eq(rule.get(2))).and(
                                    v3.eq(rule.get(3))
                                        .and(v4.eq(rule.get(4)))
                                        .and(v5.eq(rule.get(5))),
                                ),
                            ),
                        ),
                    ),
                )
                .execute(&conn)
                .map_err(DieselError::Error)
            })
            .is_ok()
    }

    fn remove_filtered_policy(
        &self,
        sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> bool {
        use schema::casbin_rules::dsl::*;

        if field_index >= 0 && field_index <= 4 && field_values.len() > 0 {
            self.pool
                .get()
                .map_err(DieselError::PoolError)
                .and_then(|conn| {
                    if field_index == 0 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v0.eq(field_values.get(0)).and(
                                        v1.eq(field_values.get(1))
                                            .and(v2.eq(field_values.get(2)))
                                            .and(
                                                v3.eq(field_values.get(3))
                                                    .and(v4.eq(field_values.get(4)))
                                                    .and(v5.eq(field_values.get(5))),
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
                                    v1.eq(field_values.get(0))
                                        .and(v2.eq(field_values.get(1)))
                                        .and(
                                            v3.eq(field_values.get(2))
                                                .and(v4.eq(field_values.get(3)))
                                                .and(v5.eq(field_values.get(4))),
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
                                    v3.eq(field_values.get(2))
                                        .and(v4.eq(field_values.get(3)))
                                        .and(v5.eq(field_values.get(4))),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else if field_index == 3 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v4.eq(field_values.get(3)).and(v5.eq(field_values.get(4))),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
                    } else {
                        diesel::delete(
                            casbin_rules.filter(ptype.eq(pt).and(v5.eq(field_values.get(4)))),
                        )
                        .execute(&conn)
                        .map_err(DieselError::Error)
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

    #[test]
    fn test_create_table() {}
}
