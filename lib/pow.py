'''
Created on 8 Jul 2016

@author: Jeroen Boonstra
'''

import util
from bitcoin import hash_encode

try:
    from ltc_scrypt import getPoWHash as getPoWScryptHash
except ImportError:
    util.print_msg("Warning: ltc_scrypt not available, using fallback")
    from scrypt import scrypt_1024_1_1_80 as getPoWScryptHash
    
try:
    from groestl_hash import getPoWHash as getPoWGroestlHash
except ImportError:
    util.print_msg("Warning: groestl_hash not available, please install it")
    raise

try:
    from skeinhash import getPoWHash as getPoWSkeinHash
except ImportError:
    util.print_msg("Warning: skeinhash not available, please install it")
    raise

try:
    from qubit_hash import getPoWHash as getPoWQubitHash
except ImportError:
    util.print_msg("Warning: qubit-hash not available, please install it")
    raise


class PoW(object):
    '''
    Proof of Work function for certain coin used by blockchain to verify block headers
    Default is litecoin
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
        return hash_encode(getPoWScryptHash(self.blockchain.serialize_header(header).decode('hex')))

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



class PoW_AUR(PoW):
    '''
    Proof of Work function for aurora coin used by blockchain to verify block headers
    '''
    ALGO_SHA256D = 0
    ALGO_SCRYPT  = 1
    ALGO_GROESTL = 2
    ALGO_SKEIN   = 3
    ALGO_QUBIT   = 4
    
    # Primary version
    BLOCK_VERSION_DEFAULT        = 2

    # Algo
    BLOCK_VERSION_ALGO           = (7 << 9)
    BLOCK_VERSION_SHA256D        = (1 << 9)
    BLOCK_VERSION_GROESTL        = (2 << 9)
    BLOCK_VERSION_SKEIN          = (3 << 9)
    BLOCK_VERSION_QUBIT          = (4 << 9)
    
    # Max target algo
    MAX_TARGET_ALGO_SHA256D = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # CBigNum(~uint256(0) >> 32);
    MAX_TARGET_ALGO_SCRYPT  = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # CBigNum(~uint256(0) >> 20);
    MAX_TARGET_ALGO_GROESTL = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # CBigNum(~uint256(0) >> 23);
    MAX_TARGET_ALGO_SKEIN   = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # CBigNum(~uint256(0) >> 23);
    MAX_TARGET_ALGO_QUBIT   = 0x000003FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # CBigNum(~uint256(0) >> 22);
    
    
    multiAlgoDiffChangeTarget = 225000; # block 225000 where multi-algo work weighting starts 225000

    def __init__(self, blockchain):
        '''
        Constructor
        '''
        super(PoW_AUR, self).__init__(blockchain)
        self.nTargetTimeSpan = 8 * 10 * 60 # Legacy 4800
        self.nTargetSpacing = 10 * 60 # 60 seconds
        self.multiAlgoNum = 5 # Amount of algos
        self.multiAlgoTimespan = 61 # Time per block per algo
        self.multiAlgoTargetSpacing = self.multiAlgoNum * self.multiAlgoTimespan
        self.nAveragingInterval = 10 # 10 blocks
        self.nAveragingTargetTimespan = self.nAveragingInterval * self.multiAlgoTargetSpacing # 10* NUM_ALGOS * 61

    def get_pow_limit(self, algo = ALGO_SCRYPT):
        maxTarget = { PoW_AUR.ALGO_SHA256D: PoW_AUR.MAX_TARGET_ALGO_SHA256D, 
            PoW_AUR.ALGO_SCRYPT: PoW_AUR.MAX_TARGET_ALGO_SCRYPT,
            PoW_AUR.ALGO_GROESTL: PoW_AUR.MAX_TARGET_ALGO_GROESTL,
            PoW_AUR.ALGO_SKEIN: PoW_AUR.MAX_TARGET_ALGO_SKEIN,
            PoW_AUR.ALGO_QUBIT: PoW_AUR.MAX_TARGET_ALGO_QUBIT }.get(algo, PoW_AUR.MAX_TARGET_ALGO_SCRYPT)

        return self.target_to_bits(maxTarget)

    def get_max_target(self, algo = ALGO_SCRYPT):
        return self.bits_to_target(self.get_pow_limit(algo))
    
    def get_algo(self, block_version):
        return { PoW_AUR.BLOCK_VERSION_SHA256D: PoW_AUR.ALGO_SHA256D,
                PoW_AUR.BLOCK_VERSION_GROESTL: PoW_AUR.ALGO_GROESTL,
                PoW_AUR.BLOCK_VERSION_SKEIN: PoW_AUR.ALGO_SKEIN,
                PoW_AUR.BLOCK_VERSION_QUBIT: PoW_AUR.ALGO_QUBIT
                }.get(block_version & PoW_AUR.BLOCK_VERSION_ALGO, PoW_AUR.ALGO_SCRYPT)
    
    def pow_scrypt_hash_header(self, header):
        return hash_encode(getPoWScryptHash(self.blockchain.serialize_header(header).decode('hex')))
    
    def pow_groestl_hash_header(self, header):
        return hash_encode(getPoWGroestlHash(self.blockchain.serialize_header(header).decode('hex')))
    
    def pow_skein_hash_header(self, header):
        return hash_encode(getPoWSkeinHash(self.blockchain.serialize_header(header).decode('hex')))
    
    def pow_qubit_hash_header(self, header):
        return hash_encode(getPoWQubitHash(self.blockchain.serialize_header(header).decode('hex')))
    
    def pow_hash_header(self, header):
        block_version = header['version'];
        getPoWHash = { PoW_AUR.ALGO_SCRYPT: self.pow_scrypt_hash_header,
                       PoW_AUR.ALGO_GROESTL: self.pow_groestl_hash_header,
                       PoW_AUR.ALGO_SKEIN: self.pow_skein_hash_header,
                       PoW_AUR.ALGO_QUBIT: self.pow_qubit_hash_header }.get(self.get_algo(block_version), self.blockchain.hash_header)
        return getPoWHash(header)

    def get_header(self, height, chain=None):
        header = self.blockchain.read_header(height)
        if header is None:
            for h in chain:
                if h.get('block_height') == height:
                    return h
        return header
        
    def get_target_original(self, height, chain=None):
        if height == 0:
            return self.get_pow_limit(), self.get_max_target()
        if height < 135:
            return self.get_pow_limit(), self.get_max_target()
        interval = self.get_difficultyAdjustmentInterval()
        last_height = height - 1
        last = self.get_header(last_height)
        assert last is not None
        # changed only once per interval
        last_target = self.bits_to_target(last['bits'])
        if (height % interval) != 0:
            return last['bits'], last_target 
        first_height = last_height - interval
        if height == interval:
            first_height = 0
        first = self.get_header(first_height, chain)
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = self.nTargetTimeSpan
        nActualTimespan = max(nActualTimespan, (nTargetTimespan * 50) / 75)
        nActualTimespan = min(nActualTimespan, (nTargetTimespan * 75) / 50)
        new_target = min(self.get_max_target(), (last_target*nActualTimespan) / nTargetTimespan)
        # convert new target to bits
        return self.normalize_target_to_bits(new_target)
        
    def kimotoGravityWell(self, height, chain, targetBlockSpacingSeconds, pastBlocksMin, pastBlocksMax):
        blockLastSolved = height - 1
        blockReading = height - 1
        #blockHeaderCreating = self.get_header(height, chain)
        
        pastBlocksMass = 0
        pastRateActualSeconds = 0
        pastRateTargetSeconds = 0
        pastRateAdjustmentRatio = 1.0
        pastDifficultyAverage = 0
        pastDifficultyAveragePrev = 0
#        eventHorizonDeviation;
#        eventHorizonDeviationFast;
#        eventHorizonDeviationSlow;
        if blockLastSolved == 0 or blockLastSolved < pastBlocksMin:
            return self.get_pow_limit(), self.get_max_target()
        
        blockHeaderLastSolved = self.get_header(blockLastSolved, chain)
        
        for i in range(1, pastBlocksMax + 1):
            if pastBlocksMax > 0 and i > pastBlocksMax:
                break
            
            blockHeaderReading = self.get_header(blockReading, chain)
            pastBlocksMass += 1
            
            if i == 1:
                pastDifficultyAverage = self.bits_to_target(blockHeaderReading['bits'])
            else:
                pastDifficultyAverage = ((self.bits_to_target(blockHeaderReading['bits']) - pastDifficultyAveragePrev) / i) + pastDifficultyAveragePrev
                
            pastDifficultyAveragePrev = pastDifficultyAverage
            
            pastRateActualSeconds =  blockHeaderLastSolved['timestamp'] - blockHeaderReading['timestamp']
            pastRateTargetSeconds = targetBlockSpacingSeconds * pastBlocksMass
            pastRateAdjustmentRatio = 1.0
            if pastRateActualSeconds < 0:
                pastRateActualSeconds = 0
            if pastRateActualSeconds != 0 and pastRateTargetSeconds != 0:
                pastRateAdjustmentRatio = float(pastRateTargetSeconds) / float(pastRateActualSeconds)
            
            eventHorizonDeviation = 1 + (0.7084 * pow((float(pastBlocksMass)/144.0), -1.228));
            eventHorizonDeviationFast = eventHorizonDeviation
            eventHorizonDeviationSlow = 1 / eventHorizonDeviation

            if pastBlocksMass >= pastBlocksMin:
                if (pastRateAdjustmentRatio <= eventHorizonDeviationSlow) or (pastRateAdjustmentRatio >= eventHorizonDeviationFast): 
                    # assert(BlockReading)
                    break
            
            #     if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
            blockReading -= 1

        new_target = pastDifficultyAverage
        if pastRateActualSeconds != 0 and pastRateTargetSeconds != 0:
            new_target *= pastRateActualSeconds
            new_target /= pastRateTargetSeconds
            
        if new_target > self.get_max_target():
            new_target = self.get_max_target()
            
        return self.normalize_target_to_bits(new_target)
    
    def get_target_KGW(self, height, chain=None):
        nBlocksTargetSpacing = 5 * 60 # 1 minute
        nTimeDaySeconds = 60 * 60 * 24
        nPastSecondsMin = nTimeDaySeconds * 0.5
        nPastSecondsMax = nTimeDaySeconds * 14
        nPastBlocksMin  = nPastSecondsMin / nBlocksTargetSpacing
        nPastBlocksMax  = nPastSecondsMax / nBlocksTargetSpacing
        return self.kimotoGravityWell(height, chain, nBlocksTargetSpacing, nPastBlocksMin, nPastBlocksMax)
    
    def get_target_Multi(self, height, chain=None):
        #TODO implement this
        return self.get_target_original(height, chain)
    
    def get_target(self, height, chain=None):
        diffMode = 1
        if height <= 5400:
            diffMode = 1
        elif height <= PoW_AUR.multiAlgoDiffChangeTarget:
            diffMode = 2
        else:
            diffMode = 3

        if diffMode == 1:
            return self.get_target_original(height, chain)
        elif diffMode == 2:
            return self.get_target_KGW(height, chain)
        elif diffMode == 3:
            return self.get_target_Multi(height, chain)
        
        return self.get_target_Multi(height, chain)
    