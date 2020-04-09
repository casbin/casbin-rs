use crate::{Adapter, DefaultModel, FileAdapter, Model, Result};

use async_trait::async_trait;

#[async_trait]
pub trait TryIntoModel {
    async fn try_into_model(self) -> Result<Box<dyn Model>>;
}

#[async_trait]
pub trait TryIntoAdapter {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>>;
}

#[async_trait]
impl TryIntoModel for &'static str {
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        Ok(Box::new(DefaultModel::from_file(self).await?))
    }
}

#[async_trait]
impl TryIntoAdapter for &'static str {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(FileAdapter::new(self)))
    }
}

#[async_trait]
impl<T> TryIntoModel for T
where
    T: Model + 'static,
{
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        Ok(Box::new(self))
    }
}

#[async_trait]
impl<T> TryIntoAdapter for T
where
    T: Adapter + 'static,
{
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(self))
    }
}
