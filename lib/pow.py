'''
Created on 8 Jul 2016

@author: Jeroen Boonstra
'''

import util
from bitcoin import rev_hex

try:
    from ltc_scrypt import getPoWHash
except ImportError:
    util.print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as getPoWHash

class PoW(object):
    '''
    Proof of Work function for certain coin used by blockchain to verify block headers
    '''


    def __init__(self, blockchain):
        '''
        Constructor
        '''
        self.blockchain = blockchain
        self.nTargetTimeSpan = 3.5 * 24 * 60 * 60 # 3.5 days
        self.nTargetSpacing = 2.5 * 60 # 2.5 minutes

    def get_pow_limit(self):
        return 0x1e0ffff0

    def get_max_target(self):
        return self.bits_to_target(self.get_pow_limit())
    
    def get_difficultyAdjustmentInterval(self):
        return self.nTargetTimeSpan / self.nTargetSpacing
        
    def pow_hash_header(self, header):
        return rev_hex(getPoWHash(self.blockchain.serialize_header(header).decode('hex')).encode('hex'))

    def bits_to_target(self, bits):
        bitsN = (bits >> 24) & 0xff
        assert bitsN >= 0x03 and bitsN <= 0x1e, "First part of bits should be in [0x03, 0x1e]"
        bitsBase = bits & 0xffffff
        assert bitsBase >= 0x8000 and bitsBase <= 0x7fffff, "Second part of bits should be in [0x8000, 0x7fffff]"
        target = bitsBase << (8 * (bitsN-3))
        return target

    def target_to_bits(self, target):
        # convert new target to bits
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        bits = bitsN << 24 | bitsBase
        return bits

    def normalize_target_to_bits(self, target):
        # convert target to bits and normalized target
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        bits = bitsN << 24 | bitsBase
        return bits, bitsBase << (8 * (bitsN-3))

    def get_target(self, height, chain=None):
        if height == 0:
            return self.get_pow_limit(), self.get_max_target()
        # Litecoin: go back the full period unless it's the first retarget
        interval = self.get_difficultyAdjustmentInterval()
        last_height = height - 1
        first = self.blockchain.read_header(last_height - interval if last_height > interval else 0)
        last = self.blockchain.read_header(last_height)
        if last is None:
            for h in chain:
                if h.get('block_height') == last_height:
                    last = h
        assert last is not None
        # bits to target
        target = self.bits_to_target(last.get('bits'))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = self.nTargetTimeSpan
        nActualTimespan = max(nActualTimespan, nTargetTimespan / 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(self.get_max_target(), (target*nActualTimespan) / nTargetTimespan)
        # convert new target to bits
        return self.normalize_target_to_bits(new_target)
