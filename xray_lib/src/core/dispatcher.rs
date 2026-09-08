use std::io;
use std::sync::Arc;

use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::outbound::Outbound;
use crate::core::router::RouteLocation;
use crate::core::router::router::Router;
use crate::core::session::Session;
use crate::core::statistics_manager::StatisticsManager;
use crate::outbound::stats::StatisticsOutbound;
use log::{info, trace, warn};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DispatcherItem {
    pub tag: String,
    pub detour: Option<String>,
    pub outbound: Box<Arc<dyn Outbound>>,
}
impl DispatcherItem {
    pub fn new(tag: String, detour: Option<String>, outbound: Box<Arc<dyn Outbound>>) -> Self {
        Self {
            tag,
            detour,
            outbound,
        }
    }
}
pub struct Dispatcher {
    router: Router,
    statistics_manager: Option<Arc<StatisticsManager>>,
}

impl Dispatcher {
    pub fn new(stats_enable: bool, router: Router) -> Result<Dispatcher, io::Error> {
        let mut statistics_manager = None;
        if stats_enable {
            statistics_manager = Some(StatisticsManager::new());
        }
        Ok(Self {
            router,
            statistics_manager,
        })
    }
    pub fn get_statistics_manager(&self) -> Option<Arc<StatisticsManager>> {
        self.statistics_manager.clone()
    }
    pub fn have_any_matcher(&self) -> bool {
        self.router.have_any_matcher()
    }
    pub async fn get_routed_outbound(
        &self,
        context: Arc<Context>,
        session: Session,
        route_location: Arc<RouteLocation>,
    ) -> Option<DispatcherItem> {
        trace!(
            "dispatcher: routing session {} to {}",
            session, route_location
        );
        let tag = self
            .router
            .get_outbound_tag(context.clone(), route_location.clone())
            .await;
        match tag {
            None => {
                info!(
                    "route session {} target {} to default outbound",
                    session,
                    route_location.clone()
                );
            }
            Some(tag) => {
                info!(
                    "route session {} target {} to outbound with tag {}",
                    session,
                    route_location.clone(),
                    tag
                );
                let outbounds = context.outbounds().await;
                let outbound = outbounds.get(&tag);
                if let Some(outbound) = outbound {
                    return match &self.statistics_manager {
                        None => Some(outbound.clone()),
                        Some(statistics_manager) => {
                            let statistics_outbound = StatisticsOutbound::new(
                                outbound.clone(),
                                statistics_manager.clone(),
                            );
                            let statistics_outbound: Box<Arc<dyn Outbound>> =
                                Box::new(Arc::new(statistics_outbound));
                            Some(DispatcherItem::new(
                                outbound.tag.clone(),
                                outbound.detour.clone(),
                                statistics_outbound,
                            ))
                        }
                    };
                }
                drop(outbounds);
                warn!(
                    "no outbound with tag '{}' found in outbounds use default outbound",
                    tag
                );
            }
        }
        let outbounds = context.outbounds().await;
        let outbound_first = outbounds.get_index(0);
        if let Some(outbound) = outbound_first {
            return match &self.statistics_manager {
                None => Some(outbound.1.clone()),
                Some(statistics_manager) => {
                    let statistics_outbound =
                        StatisticsOutbound::new(outbound.1.clone(), statistics_manager.clone());
                    let statistics_outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(statistics_outbound));
                    Some(DispatcherItem::new(
                        outbound.1.tag.clone(),
                        outbound.1.detour.clone(),
                        statistics_outbound,
                    ))
                }
            };
        }
        None
    }

    pub async fn get_with_tag(&self, context: Arc<Context>, tag: String) -> Option<DispatcherItem> {
        let outbounds = context.outbounds().await;
        let outbound = outbounds.get(&tag);
        if let Some(outbound) = outbound {
            return Some(outbound.clone());
        }
        warn!("no outbound with tag '{}' found in outbounds", tag);
        None
    }
}
