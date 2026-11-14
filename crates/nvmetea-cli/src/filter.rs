//! Object filters shared by every command. Users name things the way they see
//! them (`nvme3`, a target address, an NQN or its suffix, `nvme2n4`, a WWID).

use nvmetea_core::model::{Controller, Namespace, Subsystem, Topology};

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub controller: Option<String>,
    pub subsystem: Option<String>,
    pub namespace: Option<String>,
    pub all_transports: bool,
}

fn nqn_matches(pat: &str, name: &str, nqn: Option<&str>) -> bool {
    pat == name || nqn.is_some_and(|n| n == pat || n.ends_with(pat) || (pat.len() >= 6 && n.contains(pat)))
}

impl Filter {
    pub fn controller(&self, c: &Controller) -> bool {
        if !self.all_transports && !c.is_tcp() {
            return false;
        }
        if let Some(p) = &self.controller {
            let a = c.address.as_ref();
            let traddr = a.and_then(|a| a.traddr.as_deref());
            let ep = a.and_then(|a| Some(format!("{}:{}", a.traddr.as_deref()?, a.trsvcid.as_deref()?)));
            if !(c.name == *p || traddr == Some(p.as_str()) || ep.as_deref() == Some(p.as_str())) {
                return false;
            }
        }
        if let Some(s) = &self.subsystem {
            if !nqn_matches(s, c.subsystem.as_deref().unwrap_or(""), c.subsysnqn.as_deref()) {
                return false;
            }
        }
        true
    }

    pub fn subsystem(&self, s: &Subsystem, topo: &Topology) -> bool {
        if let Some(p) = &self.subsystem {
            if !nqn_matches(p, &s.name, s.nqn.as_deref()) {
                return false;
            }
        }
        s.controllers.iter().any(|c| topo.controller(c).is_some_and(|c| self.controller(c)))
            || (self.controller.is_none() && self.all_transports)
    }

    pub fn namespace(&self, ns: &Namespace, topo: &Topology) -> bool {
        if let Some(p) = &self.namespace {
            let hit = ns.name == *p
                || ns.wwid.as_deref() == Some(p.as_str())
                || ns.uuid.as_deref() == Some(p.as_str())
                || ns.nguid.as_deref() == Some(p.as_str());
            if !hit {
                return false;
            }
        }
        let ctrls: Vec<&str> = match &ns.controller {
            Some(c) => vec![c.as_str()],
            None => ns.paths.iter().map(|p| p.controller.as_str()).collect(),
        };
        ctrls.iter().any(|c| topo.controller(c).is_some_and(|c| self.controller(c)))
            || (ctrls.is_empty() && self.all_transports)
    }

    /// An explicit filter that matches nothing is an error, with suggestions.
    pub fn validate(&self, topo: &Topology) -> anyhow::Result<()> {
        if self.controller.is_some() && !topo.controllers.iter().any(|c| self.controller(c)) {
            let known: Vec<&str> = topo
                .controllers
                .iter()
                .filter(|c| self.all_transports || c.is_tcp())
                .map(|c| c.name.as_str())
                .collect();
            anyhow::bail!(
                "no controller matches --controller {} (known: {}){}",
                self.controller.as_deref().unwrap_or_default(),
                if known.is_empty() { "none".to_string() } else { known.join(", ") },
                if self.all_transports { "" } else { "; add --all-transports for non-TCP controllers" }
            );
        }
        if self.subsystem.is_some() && !topo.subsystems.iter().any(|s| self.subsystem(s, topo)) {
            anyhow::bail!("no subsystem matches --subsystem {}", self.subsystem.as_deref().unwrap_or_default());
        }
        if self.namespace.is_some() && !topo.namespaces.iter().any(|n| self.namespace(n, topo)) {
            anyhow::bail!("no namespace matches --namespace {}", self.namespace.as_deref().unwrap_or_default());
        }
        Ok(())
    }
}
