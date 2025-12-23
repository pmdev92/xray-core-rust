use std::io;
use std::sync::Arc;

use crate::common::net_location::NetLocation;
use crate::core::outbound::Outbound;
use crate::core::router::router::Router;
use crate::core::router::RouteLocation;
use crate::core::session::Session;
use crate::core::statistics_manager::StatisticsManager;
use crate::outbound::stats::StatisticsOutbound;
use log::{info, warn};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DispatcherItem {
    pub tag: Option<String>,
    pub detour: Option<String>,
    pub outbound: Box<Arc<dyn Outbound>>,
}
impl DispatcherItem {
    pub fn new(
        tag: Option<String>,
        detour: Option<String>,
        outbound: Box<Arc<dyn Outbound>>,
    ) -> Self {
        Self {
            tag,
            detour,
            outbound,
        }
    }
}
pub struct Dispatcher {
    outbounds: RwLock<Vec<DispatcherItem>>,
    router: Router,
    statistics_manager: Option<Arc<StatisticsManager>>,
}

impl Dispatcher {
    pub fn new(
        stats_enable: bool,
        outbounds: Vec<DispatcherItem>,
        router: Router,
    ) -> Result<Dispatcher, io::Error> {
        let mut statistics_manager = None;
        if stats_enable {
            statistics_manager = Some(StatisticsManager::new());
        }
        Ok(Self {
            outbounds: RwLock::new(outbounds),
            router,
            statistics_manager,
        })
    }
    pub fn get_statistics_manager(&self) -> Option<Arc<StatisticsManager>> {
        return self.statistics_manager.clone();
    }
    pub fn have_any_matcher(&self) -> bool {
        self.router.have_any_matcher()
    }
    pub async fn get_routed_outbound(
        &self,
        session: Session,
        route_location: Arc<RouteLocation>,
    ) -> Option<DispatcherItem> {
        let tag = self.router.get_outbound_tag(route_location.clone());
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
                for item in self.outbounds.read().await.iter() {
                    let outbound_tag = &item.tag;
                    match outbound_tag {
                        None => {}
                        Some(outbound_tag) => {
                            if outbound_tag == &tag {
                                return match &self.statistics_manager {
                                    None => Some(item.clone()),
                                    Some(statistics_manager) => {
                                        let statistics_outbound = StatisticsOutbound::new(
                                            item.clone(),
                                            statistics_manager.clone(),
                                        );
                                        let statistics_outbound: Box<Arc<dyn Outbound>> =
                                            Box::new(Arc::new(statistics_outbound));
                                        Some(DispatcherItem::new(
                                            item.tag.clone(),
                                            item.detour.clone(),
                                            statistics_outbound,
                                        ))
                                    }
                                };
                            }
                        }
                    }
                }
                warn!(
                    "no outbound with tag '{}' found in outbounds use default outbound",
                    tag
                )
            }
        }
        let outbounds = self.outbounds.read().await;
        if outbounds.len() > 0 {
            return match &self.statistics_manager {
                None => Some(outbounds[0].clone()),
                Some(statistics_manager) => {
                    let statistics_outbound =
                        StatisticsOutbound::new(outbounds[0].clone(), statistics_manager.clone());
                    let statistics_outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(statistics_outbound));
                    Some(DispatcherItem::new(
                        outbounds[0].tag.clone(),
                        outbounds[0].detour.clone(),
                        statistics_outbound,
                    ))
                }
            };
        }

        return None;
    }

    pub async fn get_with_tag(&self, tag: String) -> Option<DispatcherItem> {
        let outbounds = self.outbounds.read().await;
        for item in outbounds.iter() {
            let outbound_tag = &item.tag;
            match outbound_tag {
                None => {}
                Some(outbound_tag) => {
                    if outbound_tag == &tag {
                        return Some(item.clone());
                    }
                }
            }
        }
        warn!("no outbound with tag '{}' found in outbounds", tag);
        return None;
    }

    pub async fn destroy(&self) {
        let mut outbounds = self.outbounds.write().await;
        *outbounds = vec![];
    }
}
