/*++

Licensed under the Apache-2.0 license.

File Name:

    mrac_bus.rs

Abstract:

    Optional emulation of the VeeR EL2 MRAC (Memory Region Access Control)
    register. Wraps an inner Bus and enforces per-region access rules:

    - Side-effect regions: only word-aligned, word-sized access allowed.
    - Cacheable regions: reads are widened to 64-bit aligned double-word
      fetches (two word reads from the inner bus).

    Ref: https://chipsalliance.github.io/Cores-VeeR-EL2/html/main/docs_rendered/html/memory-map.html#region-access-control-register-mrac

--*/

use std::cell::Cell;
use std::rc::Rc;
use std::sync::mpsc;

use crate::bus::{Bus, BusError};
use crate::event::Event;
use caliptra_emu_types::{RvAddr, RvData, RvSize};

/// Bus wrapper that enforces VeeR EL2 MRAC region access rules.
///
/// The 32-bit address space is split into 16 regions of 256MB each.
/// Each region has a 2-bit field in the MRAC CSR (0x7C0):
///   - bit Y*2:   cacheable
///   - bit Y*2+1: sideeffect
///
/// When `enabled` is false, all accesses pass through unchanged.
pub struct MracBus<TBus: Bus> {
    inner: TBus,
    mrac: Rc<Cell<u32>>,
    enabled: bool,
}

impl<TBus: Bus> MracBus<TBus> {
    pub fn new(inner: TBus, mrac: Rc<Cell<u32>>, enabled: bool) -> Self {
        Self {
            inner,
            mrac,
            enabled,
        }
    }

    /// Extract the 2-bit region field for a given address.
    fn region_bits(&self, addr: RvAddr) -> u32 {
        let region = (addr >> 28) & 0xF;
        (self.mrac.get() >> (region * 2)) & 0b11
    }

    fn is_sideeffect(&self, addr: RvAddr) -> bool {
        self.region_bits(addr) & 0b10 != 0
    }

    fn is_cacheable(&self, addr: RvAddr) -> bool {
        self.region_bits(addr) & 0b01 != 0
    }

    /// Return a mutable reference to the inner bus.
    pub fn inner_mut(&mut self) -> &mut TBus {
        &mut self.inner
    }

    /// Return a reference to the inner bus.
    pub fn inner(&self) -> &TBus {
        &self.inner
    }
}

impl<TBus: Bus> Bus for MracBus<TBus> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if !self.enabled {
            return self.inner.read(size, addr);
        }

        if self.is_sideeffect(addr) {
            // Side-effect: only word-aligned, word-sized access
            if size != RvSize::Word || (addr & 0x3) != 0 {
                return Err(BusError::LoadAddrMisaligned);
            }
            return self.inner.read(size, addr);
        }

        if self.is_cacheable(addr) {
            // Cacheable: widen to 64-bit aligned read (two word reads)
            let aligned_addr = addr & !0x7;
            let lo = self.inner.read(RvSize::Word, aligned_addr)?;
            let hi = self.inner.read(RvSize::Word, aligned_addr + 4)?;

            // Return the requested portion
            let dword: u64 = (lo as u64) | ((hi as u64) << 32);
            let byte_offset = (addr - aligned_addr) as usize;
            let result = match size {
                RvSize::Byte => ((dword >> (byte_offset * 8)) & 0xFF) as u32,
                RvSize::HalfWord => ((dword >> (byte_offset * 8)) & 0xFFFF) as u32,
                RvSize::Word => ((dword >> (byte_offset * 8)) & 0xFFFF_FFFF) as u32,
                _ => return Err(BusError::LoadAccessFault),
            };
            return Ok(result);
        }

        // Neither side-effect nor cacheable: pass through
        self.inner.read(size, addr)
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if !self.enabled {
            return self.inner.write(size, addr, val);
        }

        if self.is_sideeffect(addr) {
            // Side-effect: only word-aligned, word-sized access
            if size != RvSize::Word || (addr & 0x3) != 0 {
                return Err(BusError::StoreAddrMisaligned);
            }
        }

        // Cacheable writes pass through with their original size
        self.inner.write(size, addr, val)
    }

    fn poll(&mut self) {
        self.inner.poll();
    }

    fn warm_reset(&mut self) {
        self.inner.warm_reset();
    }

    fn update_reset(&mut self) {
        self.inner.update_reset();
    }

    fn incoming_event(&mut self, event: Rc<Event>) {
        self.inner.incoming_event(event);
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.inner.register_outgoing_events(sender);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::FakeBus;

    fn make_mrac_bus(mrac_val: u32, enabled: bool) -> MracBus<FakeBus> {
        let mrac = Rc::new(Cell::new(mrac_val));
        let fake = FakeBus::new();
        MracBus::new(fake, mrac, enabled)
    }

    #[test]
    fn test_disabled_passthrough() {
        let mut bus = make_mrac_bus(0xFFFF_FFFF, false);
        // Even with all regions side-effect, disabled should pass through
        assert!(bus.read(RvSize::Byte, 0x3003_0001).is_ok());
        assert!(bus.write(RvSize::Byte, 0x3003_0001, 0x42).is_ok());
    }

    #[test]
    fn test_sideeffect_word_aligned_ok() {
        // Region 3 (0x3xxx_xxxx): set sideeffect bit = bit 7 (region 3 * 2 + 1)
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert!(bus.read(RvSize::Word, 0x3003_0000).is_ok());
        assert!(bus.write(RvSize::Word, 0x3003_0000, 0x42).is_ok());
    }

    #[test]
    fn test_sideeffect_byte_rejected() {
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::Byte, 0x3003_0001),
            Err(BusError::LoadAddrMisaligned)
        );
        assert_eq!(
            bus.write(RvSize::Byte, 0x3003_0001, 0x42),
            Err(BusError::StoreAddrMisaligned)
        );
    }

    #[test]
    fn test_sideeffect_halfword_rejected() {
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::HalfWord, 0x3003_0000),
            Err(BusError::LoadAddrMisaligned)
        );
    }

    #[test]
    fn test_sideeffect_misaligned_word_rejected() {
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::Word, 0x3003_0002),
            Err(BusError::LoadAddrMisaligned)
        );
    }

    #[test]
    fn test_cacheable_read_widens() {
        // Region 5 (0x5xxx_xxxx): set cacheable bit = bit 10 (region 5 * 2)
        let mrac_val = 1 << 10; // cacheable for region 5
        let mut bus = make_mrac_bus(mrac_val, true);
        // FakeBus returns Ok(0) by default, so widened read should succeed
        assert!(bus.read(RvSize::Byte, 0x5000_0001).is_ok());
        assert!(bus.read(RvSize::HalfWord, 0x5000_0002).is_ok());
        assert!(bus.read(RvSize::Word, 0x5000_0004).is_ok());
    }

    #[test]
    fn test_no_flags_passthrough() {
        // Region 2: no flags set
        let mut bus = make_mrac_bus(0, true);
        assert!(bus.read(RvSize::Byte, 0x2000_0001).is_ok());
        assert!(bus.write(RvSize::Byte, 0x2000_0001, 0x42).is_ok());
    }

    #[test]
    fn test_cacheable_widens_causes_spurious_lock() {
        // Demonstrates the problem: reading USER (offset 0x04) in a
        // cacheable region widens to 64-bit, causing a read at offset 0x00
        // (LOCK) which has side effects (acquires the lock).
        let mrac_val = 1 << 6; // cacheable for region 3
        let mut bus = make_mrac_bus(mrac_val, true);

        // Read USER at 0x3002_0004 -- should widen to 64-bit aligned read
        let _ = bus.read(RvSize::Word, 0x3002_0004);

        // The widened read should have issued two word reads starting at
        // the 64-bit aligned boundary (0x3002_0000)
        let log = bus.inner().log.take();
        assert!(
            log.contains("read(RvSize::Word, 0x30020000)"),
            "Cacheable read should widen to include LOCK addr 0x30020000, got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x30020004)"),
            "Cacheable read should also read USER addr 0x30020004, got: {log}"
        );
    }

    #[test]
    fn test_sideeffect_prevents_spurious_lock() {
        // With side-effect correctly set for region 3, only the exact
        // register is read -- no widening, no spurious LOCK access.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);

        let _ = bus.read(RvSize::Word, 0x3002_0004);

        let log = bus.inner().log.take();
        assert!(
            !log.contains("0x30020000"),
            "Side-effect read should not touch LOCK addr, got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x30020004)"),
            "Only USER addr should be read, got: {log}"
        );
    }
}
