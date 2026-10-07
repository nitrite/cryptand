//! `13-operations.md` §5 — keyslot management: `add_key()`, `remove_key()`,
//! `crypto_erase()`. Each is one superblock write (two for the erase); no
//! data page is touched and the master key never changes (F-072).

use crate::container::Durability;
use crate::engine::Engine;
use crate::error::{invalid, Result};
use crate::security::{keyslot, make_keyslot, Keyslot};

pub trait KeyApi {
    /// Wraps the current master key under a new credential in the first free
    /// keyslot and returns its index. `kdf` 0 is a raw 32-byte key, 1 Argon2id.
    fn add_key(&mut self, credential: &[u8], kdf: u8, t_cost: u32, m_cost_kib: u32, lanes: u32, label: &str)
        -> Result<u8>;
    /// Drops a keyslot. Removing the last occupied one is crypto-erase and
    /// MUST be asked for by name, so it is refused here.
    fn remove_key(&mut self, slot: u8) -> Result<()>;
    /// `14-security.md` §8.2: zero every keyslot in **both** superblock slots.
    /// Irreversible.
    fn crypto_erase(&mut self) -> Result<()>;
}

fn slots(e: &Engine) -> Result<Vec<Keyslot>> {
    (0..keyslot::COUNT).map(|i| Keyslot::parse(&e.sb.keyslots[i * keyslot::SIZE..(i + 1) * keyslot::SIZE])).collect()
}

fn require_encrypted(e: &Engine) -> Result<()> {
    if e.sb.cipher == 0 || e.keys.is_none() {
        return invalid("the file is not encrypted, or is not unlocked");
    }
    Ok(())
}

impl KeyApi for Engine {
    fn add_key(&mut self, credential: &[u8], kdf: u8, t_cost: u32, m_cost_kib: u32, lanes: u32, label: &str)
        -> Result<u8> {
        require_encrypted(self)?;
        let Some(free) = slots(self)?.iter().position(|s| !s.occupied) else {
            return invalid(format!("all {} keyslots are occupied", keyslot::COUNT));
        };
        let master = *self.keys.as_ref().unwrap().master_key();
        let slot = make_keyslot(&master, &self.sb.database_uuid, free as u8, credential, kdf, t_cost, m_cost_kib, lanes, label)?;
        self.sb.keyslots[free * keyslot::SIZE..(free + 1) * keyslot::SIZE].copy_from_slice(&slot.encode());
        self.commit(Durability::Sync)?;
        Ok(free as u8)
    }

    fn remove_key(&mut self, slot: u8) -> Result<()> {
        require_encrypted(self)?;
        let i = slot as usize;
        if i >= keyslot::COUNT {
            return invalid(format!("keyslot {slot} does not exist"));
        }
        let all = slots(self)?;
        if all[i].occupied && all.iter().filter(|s| s.occupied).count() <= 1 {
            return invalid("removing the last occupied keyslot is crypto-erase; call crypto_erase() by name");
        }
        // 14 §8.2: zeros, not merely state = 0.
        self.sb.keyslots[i * keyslot::SIZE..(i + 1) * keyslot::SIZE].fill(0);
        self.commit(Durability::Sync)?;
        Ok(())
    }

    fn crypto_erase(&mut self) -> Result<()> {
        require_encrypted(self)?;
        self.sb.keyslots[..keyslot::COUNT * keyslot::SIZE].fill(0);
        // Two commits: one per superblock slot, since either may hold an intact copy.
        self.commit(Durability::Sync)?;
        self.commit(Durability::Sync)?;
        Ok(())
    }
}
