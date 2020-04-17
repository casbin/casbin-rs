use crate::{DefaultModel, FileAdapter, Model, NullAdapter, Result};

#[cfg(not(feature = "filtered-adapter"))]
use crate::Adapter;
#[cfg(feature = "filtered-adapter")]
use crate::FilteredAdapter;
use async_trait::async_trait;

#[async_trait]
pub trait TryIntoModel: Send + Sync {
    async fn try_into_model(self) -> Result<Box<dyn Model>>;
}

#[cfg(not(feature = "filtered-adapter"))]
#[async_trait]
pub trait TryIntoAdapter: Send + Sync {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>>;
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
pub trait TryIntoFilteredAdapter: Send + Sync {
    async fn try_into_filtered_adapter(self) -> Result<Box<dyn FilteredAdapter>>;
}

#[async_trait]
impl TryIntoModel for &'static str {
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        Ok(Box::new(DefaultModel::from_file(self).await?))
    }
}

#[async_trait]
impl<T> TryIntoModel for Option<T>
where
    T: TryIntoModel,
{
    async fn try_into_model(self) -> Result<Box<dyn Model>> {
        if let Some(m) = self {
            m.try_into_model().await
        } else {
            Ok(Box::new(DefaultModel::default()))
        }
    }
}

#[cfg(not(feature = "filtered-adapter"))]
#[async_trait]
impl TryIntoAdapter for &'static str {
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(FileAdapter::new(self)))
    }
}

#[cfg(not(feature = "filtered-adapter"))]
#[async_trait]
impl<T> TryIntoAdapter for Option<T>
where
    T: TryIntoAdapter,
{
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        if let Some(a) = self {
            a.try_into_adapter().await
        } else {
            Ok(Box::new(NullAdapter))
        }
    }
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
impl TryIntoFilteredAdapter for &'static str {
    async fn try_into_filtered_adapter(self) -> Result<Box<dyn FilteredAdapter>> {
        Ok(Box::new(FileAdapter::new(self)))
    }
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
impl<T> TryIntoFilteredAdapter for Option<T>
where
    T: TryIntoFilteredAdapter,
{
    async fn try_into_filtered_adapter(self) -> Result<Box<dyn FilteredAdapter>> {
        if let Some(a) = self {
            a.try_into_filtered_adapter().await
        } else {
            Ok(Box::new(NullAdapter))
        }
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

#[cfg(not(feature = "filtered-adapter"))]
#[async_trait]
impl<T> TryIntoAdapter for T
where
    T: Adapter + 'static,
{
    async fn try_into_adapter(self) -> Result<Box<dyn Adapter>> {
        Ok(Box::new(self))
    }
}

#[cfg(feature = "filtered-adapter")]
#[async_trait]
impl<T> TryIntoFilteredAdapter for T
where
    T: FilteredAdapter + 'static,
{
    async fn try_into_filtered_adapter(self) -> Result<Box<dyn FilteredAdapter>> {
        Ok(Box::new(self))
    }
}
