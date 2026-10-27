//! Bounded recent state. Durable history lives in SQLite, independently of this cache.
use std::collections::{BTreeSet, HashMap};

pub struct Recent<T> {
    values: HashMap<String, (u64, T)>,
    order: BTreeSet<(u64, String)>,
    capacity: usize,
}
impl<T> Recent<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            values: HashMap::new(),
            order: BTreeSet::new(),
            capacity,
        }
    }
    pub fn insert(&mut self, key: String, ts: u64, value: T) {
        self.insert_evicting(key, ts, value);
    }
    pub fn insert_evicting(&mut self, key: String, ts: u64, value: T) -> Option<T> {
        if let Some((old, _)) = self.values.remove(&key) {
            self.order.remove(&(old, key.clone()));
        }
        self.order.insert((ts, key.clone()));
        self.values.insert(key, (ts, value));
        if self.values.len() > self.capacity
            && let Some((_, key)) = self.order.pop_first()
        {
            return self.values.remove(&key).map(|(_, v)| v);
        }
        None
    }
    pub fn remove(&mut self, key: &str) -> Option<T> {
        let (ts, value) = self.values.remove(key)?;
        self.order.remove(&(ts, key.to_string()));
        Some(value)
    }
    pub fn entries(&self) -> impl Iterator<Item = (&String, &T)> {
        self.values.iter().map(|(k, (_, v))| (k, v))
    }
    pub fn get(&self, key: &str) -> Option<&T> {
        self.values.get(key).map(|(_, v)| v)
    }
    pub fn touch(&mut self, key: &str, ts: u64) {
        if let Some((old, _)) = self.values.get_mut(key) {
            self.order.remove(&(*old, key.to_string()));
            *old = ts;
            self.order.insert((ts, key.to_string()));
        }
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        self.values.get_mut(key).map(|(_, v)| v)
    }
    pub fn get_or_insert_with(
        &mut self,
        key: String,
        ts: u64,
        create: impl FnOnce() -> T,
    ) -> &mut T {
        if self.get(&key).is_none() {
            // Admit the new entry even when records arrive out of timestamp order.
            if self.values.len() >= self.capacity
                && let Some((_, old)) = self.order.pop_first()
            {
                self.values.remove(&old);
            }
            self.insert(key.clone(), ts, create());
        } else {
            self.touch(&key, ts);
        }
        self.get_mut(&key)
            .expect("recent cache capacity must be positive")
    }
    pub fn expire_before(&mut self, cutoff: u64) {
        while self.order.first().is_some_and(|(ts, _)| *ts < cutoff) {
            let (_, key) = self.order.pop_first().unwrap();
            self.values.remove(&key);
        }
    }
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.values.values().map(|(_, v)| v)
    }
    pub fn recent(&self, limit: usize) -> impl Iterator<Item = &T> {
        self.order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|(_, k)| self.get(k))
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.values.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn updates_reorder_and_capacity_evicts_oldest() {
        let mut c = Recent::new(2);
        c.insert("a".into(), 1, 1);
        c.insert("b".into(), 2, 2);
        c.insert("a".into(), 3, 3);
        c.insert("c".into(), 4, 4);
        assert!(c.get("b").is_none());
        assert_eq!(c.recent(2).copied().collect::<Vec<_>>(), vec![4, 3]);
        assert_eq!(c.len(), 2);
        c.touch("a", 5);
        c.insert("d".into(), 6, 6);
        assert!(c.get("c").is_none());
        assert_eq!(c.recent(2).copied().collect::<Vec<_>>(), vec![6, 3]);
    }
}
