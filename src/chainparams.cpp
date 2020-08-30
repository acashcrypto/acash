// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'ACASH' + blake2s(b'Crypto News 2018-06-20 A New Innovative Cryptocurrency is Born. BTC #584776 - 0000000000000000001735245dc4f654e91d29a67a6c9220fdf34400797dcdcc').hexdigest()
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "ACASHffac10d46a9b798df8ca7c8997e0120aa3cedd5db2237b19a1f4e860e2210a19";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ACH";
        bip44CoinType = 348; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 32;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 780006;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1690;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 780006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1690;

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000a95cc5099213e3");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04d5212ed0303c64db1840e799d31953eb362fd71d8e742dccd9aa78c4713d6d26b44974b44e2ac71aa38b06ef60c020207b85d270e4bdf8c797f3216f969960dc");
        nDefaultPort = 2020;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        newTimeRule = 159300;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 1900010;
        eh_epoch_2_startblock = 1900000;

        genesis = CreateGenesisBlock(
            1562754479,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000060e"),
            ParseHex("00665b56d61db1d16271503b0eb6093dab4739c1f10a85265e6a67eeb5b2fc30e7520861c864769d0fc22a0d4abc8219a05f54b1952567b3f27967939668fc3aad5b9fdfd5df4ffbd5d6767b7e28aef5b69c7f8c0176e45a25495c51b444b139250f69005be176bba112af2d236f59751d834deb04bdf50c3b67aa9d705f1430f77bec69d37f875402cc2ab55858c30f92e1fd67d7bd52d55d0da3d412b686b0cb83fdfa68d3fb810182858ce02119e7e383011d99f4250ebf813e632f3f3e5b2ecc2d6dcfdd73c4f9c152cfce7ecc1dba4c07060931b266b1c98b8744508db83061e61a3843d853eebbee69a42d477deaebe13a694403307c9cb92804e89b062b85e97ed1ec262243650c3d90ee5169f10ea7aaac6a16a7db49fe74cb46b1cca5e6bc7adb1c24320b2effb626e9dce964ae76fc96dd346638d1c55dd6d36326a1f887d03d186cc67ab9aaaa10f7ee8d017584d85f4e5c62dd095057991cc5857675f81411054638ff5c09cdcaf43e11f5787056f115dd6f8b770e42cd1a5d14d61be58e365412d92c6354e43ce04f3c928fcae7fcbe0df08d9647c1c5aca1e55770abb702c791d8e42063cd636b9556d2fc16f9845ab0e26123d5d925b89006c3a2da9261ce679021f04ff5a45802d7fb768c61fd41f43796123eedd6f9bd7f57bf4213a78b76ee8dd182ccaaf36f742b2d56c873dba3d702ab10626a91bb6a9f71d08e697dd1cdc6c9f14fd7052f9d76d71cbbc3bd8bf0edd90f1f7eafa7589f0b042b6a947ec42692d4c8c05c756f8b74966f9b06b809daa661bafcb539e62011f5009457d35076df470809dbef4b405a1d3d27251444a2293c2dd2b17396b420cf2bae532890954e8c224dddeca9d5e3f13f6287233e4efbd6a48945e24c957965bac6168fac7b2b69489cc47740d9bc617a2824db4ecbc962011f1c78f1008f7638ed125b31d87bb079a0207dd49590549d8e188592943de5c5b3592343bdccc42181151c8966be1d810715e41b7f3febf4342caee0b3bb66809ee70a438f8235ded3aab563c9e9bfad646da71f4e1a4f7a05dfe5b7d4e74227a25f62847f1476e4ebb42fc9c646d2db5cff60af49d0aad4a247f684416695fa13ea0abd25db94de5c29b20d90e094a8fcd921cc2e80ec55bc230d643608dffc94864091bced72ba759cfa4e03f918a4185cb835946b849b9d6c1755ca2d32cb1d6d9d3e3b48714fe1a5b8270a0372f2f2f85b184a0d34834a7314cf9916ae875824fdf76166dcf6f9571e4f8443928b609563d7d5498768ef7562a5f69aee0b0a85791c5426a2c565a3b0bbab0f061d73b3f5e24237f9555343f1f4839c9124aa022adda2b199566652103475029d46407f5a57534408a976ae018b14ccf22033f67721cb413f635824330056ab32921195dc7d027664158d0d620ad0d084be674690a189e0f058010da9e1af515e2ac53d945716f45ad505d68e7ff971045d5fb69017f9436b92c10340d12988bdaadb01fd1e6f37046a0c9e90d6da03b85ad9bcfcfc47c92d1b03b728c4914ff650987bc17bfb5c2d0193978ea0510cbecefd788720d688f6816a26f93168a0337f3bbb16903c75c907ccf6a331d1f1ca795be87f0014fb1d56ec62fb6995c4b4c09a7643f4bd972a83fd5a36ac04266d9192b1f133a1a2328c23e1b30f73269c9c0a262d6c2785a2b5b77e48f5da49d57941b451752ef606f420dbc1207bfdc19f34309ca4e6896c9711028f0edc2a0521d3ed7fa34139606573b3f2a0bbbee48218acb5b773f4d8b5f9bca19fdf8e4ac91dc2cc4e4f19d63d06474816d85fee05b9622ea6267bf516ce11290704a7c59461acd2a6b4309626f7ca078fbe2c673a888fe864a08c25a6bc33e7c474c766730f74684c"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00053dfefe2ff74e59fb50126bacd8a3a0449fa6cd2e6f5213a70252f36d45ed")); //incremented by 1 making 2
        assert(genesis.hashMerkleRoot == uint256S("0x93d1db6b19bf2fed04b3ba59cceb1161bac16c58f860682e78551e58fb706227"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // use name as: echo -n hostname | sha256sum
        vSeeds.push_back(CDNSSeedData("167.172.15.74", "167.172.15.74"));
        vSeeds.push_back(CDNSSeedData("acashex.info/dnsseed", "dnsseed.acashex.info"));
       // vSeeds.push_back(CDNSSeedData("67f534b87f9a2412f845e39102f184e3a48798ed6e2a64d98b915aa12b625e9c.ACH", "seed.ach.life"));



        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x00053dfefe2ff74e59fb50126bacd8a3a0449fa6cd2e6f5213a70252f36d45ed"))
            ( 1736, uint256S("0x0007be5409205000aeda99461283d2f310dcc9bc1be18ba5c495f49d0c4fe436")),

            1586770827,     // * UNIX timestamp of last checkpoint block
            1737,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            6675  // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Community Fee script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "t3bFpARcsV3V1cybhk5r7LDhqh59DrQukao",
            "t3QZHNWxWF42UKiTGWWx9dnuXZ5yoJxYuWX",
            "t3ahbhre41nfjy9zjt685Dzq52Lh6omTykM",
            "t3SBgJZYc858Ss5khbEGsaowifjJVsYubmr",
            "t3M3XLV16go9tjv9pjWVW68aB4ZLHjpJBL4",
            "t3NsZiEiT1piNgE3CRu2A824c5N9HbHQGXT",
            "t3Q6qe9Ro1fe89tZSFgdrizK3JEeRqzMTPL",
            "t3MknTTWDSSJo4LhmHz45N9h1VJSZMbzKmg",
            "t3XtYnU7ETq3vZ3fq9Y4JGCk1XUzmG3Hw6c",
            "t3fYjEAKj39VSRvCLUEShzVMSnBjoH7J3fK",
            "t3M33v4HAaMbfnFq6YSdZEsS3QH1tNMRTKk",
            "t3TkLvxuYFvBJB1FwQYJ4EFtco53jNMF4BS",
            "t3XCWeCXakhRUQ8ejv52kqUeqzw81wYEDTX",
            "t3RGZatP9puLy26eju83SUWqK9ck5RcMa9i",
            "t3d667Dyc9gVuynkk2gWfthg1zp3athGAe8",
            "t3eLgwW6xdcEvS65hePwPjPrkUULeizu1B4",
            "t3STg5tdo1U8c8qcG9QRsJ2VtYJvQYVPHCw",
            "t3cRZqxeMoBRQHNVYjdZuv3WpFBqny7Vcja",
            "t3Xw28DggLzUVnRegKq8jwLKhX8P8w6azPP",
            "t3cgDPbg1CqKSDMmfYy9ChKa3962WckphWu",
            "t3QZGDv96FgXSVDyH1XxeJJPqise8FcUuQJ",
            "t3gzhwpCfabmxNxLQi4Czqa4bNwjHxDc9Re",
            "t3REHmTeMDZTGr1MdpaBveu8vFpCu9D8DNm",
            "t3ZLYa4YSP9AS5oxmDtKUA4BxJeT8sKiH5a",
            "t3SvUieQWuUyXAFfgMvGzFvdxxq563aLR2L",
            "t3N6J3paymKAEKgqQ1iMw3eAZfWX9Dd7wz8",
            "t3NakpJ2X1D9c9YsDJHxBqru6opsUPFWaJ3",
            "t3KPGSjcYwuXSKcbfHK88cfoxNdVKQ7fCJj",
            "t3QtX1Bn3fXJwaGSbcikcfgYf3s9LwRks2d",
            "t3XXoMQvmgst7ifbuMuA139mzs6m1GYaXZS",
            "t3QJmk4JFnfeCZBFaqiTrZwwPDrRrfrngt4",
            "t3gsmryvSDiL4RnPnMP3kgUQEQyQ1H7D3qa",
            "t3R4Akw67pwPgkLnKUuaHzQEcKGxhpNBZPN",
            "t3PzgEFDMvJaDv4x5T1RRxYwCUymnWTB3fV"
        };
        vCommunityFeeStartHeight = 1685;
        vCommunityFeeLastHeight = 3499960;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAC";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 34;
        consensus.nPowMaxAdjustUp = 34;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 780006;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 780006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1500;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000005000");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 12020;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        newTimeRule = 159300;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 1210;
        eh_epoch_2_startblock = 1200;

        genesis = CreateGenesisBlock(
            1562754579,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000023"),
            ParseHex("0006eb0463536d713c3808eb47e9409f22959d32a104e70c451b144970b7e23179dbe7732c6b34093ac90090bca15a64dacfcc09a73efac67ddf8d6ffda19c094467910249503b695152f8154ac1ed774ad00f390a98de2d44c7697c483061ace2d25ece50de1738641e2d3b341316302117762595b7c765fb80979c39312c01cdc509d47cb1504319c3c87f31c27e1878d1ef458bc5c92129207556afb4c1adf72f2e6170f9e5850047ce1725d91088fb59b69314730015e8b294f95808b9377650c4de3ccc6a385013cb59af24397a41e0036c65ceb140f81d9bc7e458545d57f654ab3d944415aec978b68af828df1b689bfc6f08672bfabab6a4148099d405ddb4191adc42554f9d5718e5832b12997f1144dad6af7ebff994c8744ec78957114e7e990a2b00a41ea5e7fd13f28af3a76eafee3d2492b2dddc3d58e47612a1323dd3bc8413cfa3e44dffa17472340a44ee738de84221918d41999a7a8074fd67f17c030bc67bc67267e575c0d5082ba35e60cb37217d15c0144d6b32c833670fcfae858d8660683d6f3bd3195f41c14e3f86a25f4320e2d789b2fa8fd682cf5565d21ac4a141075df209518dc26f9f488305919970e517323625c2f6dcee1d93b63418b5ab786edaec7b202a1b3512444e084734b081d9af53f49c13a32abddfdd6a70867d3f710925e1eed6bb3f4ece2ea69fdddfd80d039f2f770c4a9e89e3d1a17d5efaa99954d00eba28c4cd50c01ca57fbe56c4c029c156ff90a5feaddf197f4b5a8d939d43f6d9374b5ee2391b084dfca34c25a0d2d1a06216f324bdd321cc1b958d2b7bd715990ec7f97b7a547449819263483e32bcbac67bda16b935e37e494896f486cb8da4e62871ec9e08439eaec1271cfdc26fd2ec30b5aafbc0817b48ab7bc63eeaff2f878f6b4b8d1ddebc72d64cdb6e125e0872337752009df69cfc05449b4aa3f1d6d575d6fde6b8bfb3b131d946128b4f623eefa807c9026bafe737bbfce78f0cac84800f0ecd9ac8a9791e8d5d7f96a2011651e24767abc0805d406b22f17b35a460006341b11ec2f20362a2cb5731ca6dbbee4082facd8a91077d8c52cf11c57195aa5fb20b81afb37be32ca1fd950e349c460cead2b248d4109adfd086670a551421aa3d398a401e373f2005a351d7497de552feb3ba2da49b70d62701b22be12fc4b3578d955231d22d5b3961e355dd1c15907beb3350925f74fd11d836de8d2a490d9e32e419f72f861c9056c35d16d26361ecb7c18ab4f7ac0a1fc3e2162c1b68eff49a12e6c7c35c35a2745e6b6d0a4cbf3af58c238aa15cf4821f3eb60e15c61e1ca30b0781fffb1e6f0f978362ab05ef19d95ec5deb9361963a72ad74939452910f1fda5dc32baa0999d193b21ba59b74b1fbecf413c36030be26c71d3555855f407772737e10236b1b93900e4706df65d4ab03d80ed0be2f3dbfc096373d9f092bcb04d5351fc50f0718d108c84dd07c69e2a5e59d1f1945bcf618de7d76ff525b1ef000850a00b24429aa98b5a3b62d2eddbb04a1ab84f6101df001f0b4ba42c0ea91aebd4ea5fc35f60a5dcebe9987ca93bf4268a6fd5785a8dba7ad1c53e0883a0e6915f22d2dc4943c3efb5e2a4027ce23153e4274ef2ef7653fd6b0657d84ec49624f5fc22a50d6dc6e2a3c6fda4bbd3d40d07ff382d8338d33c33280ff9d41edc726b62a942b9412b5c4935d295f290148ad0c1941280ed3c6c15145fc253baa233de5ba1344dc1f3171210271fa0444532e325d23290983b1b0f02bc9a7acb892bfbf2255ebacbedbee8643d04f017121a25a1cf05c48bb7f29166e2427a9d8e95684c31693d533a4cedd874db6ad00cf2a00325685fc1ad6257b6f7497126d9ce45aa51b75eaf22ee6ffda999"),
            0x2007ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0713458baba6ad7e838c28f018ba2bdd275e35c4215ea23b59c4585fb3b76b23"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("978b674532d58328c4da63ab138c476ffa2f8a8b2b5a023a668fd3a97eb7c48b.TZB", "testnetseed.ach.biz"));
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "t2FpKCWt95LAPVRed61YbBny9yz5nqexLGN",
            "t2RqJNenxiDjC5NiVo84xgfHcYuwsPcpCie",
            "t2MsHkAug2oEiqj4L5ZGZH1vHmdogTSb9km",
            "t2EwBFfC96DCiCAcJuEqGUbUes8rTNmaD6Q",
            "t2JqYXRoTsKb9r1rTLLwDs5jMXzsRBV317k",
            "t2RocidGU4ReKPK2uTPYfNFgeZEWDCd3jsj",
            "t2Mu8ToNiVow92PfETBk5Z6HWuAEG7RVXVD",
            "t2MSLT1n4eQ87QC2FAxMvuTZ84zDzEj7FhQ",
            "t2JZNFrWv1c4RqkCmDN9iRkPsG8xAZFdyGS",
            "t2AyjEVUCf5jthGHZjwfbztDBHQbztkJB5v",
            "t2Gs6dTYCzaFdHSeT91zaFLKmYzyqYY3NnP",
            "t2FXfNK7iQhTdMFcGUyrizqXQE5qbmPK6zc",
            "t2UqLwQ85pR1fdFMoUzXadXRB97JxP6vTWY",
            "t2BocGBq7iBXQP8UQiousNVwU8M6AqUtaRx",
            "t2VGGdXhspjF3iQvbWZW2zPNSDRSYauBcM3",
            "t2HTNHicoeEXxsX1wVhsqsX3LgzRq2pYgWH",
            "t2UiVSyM1vuvs6xP3157ytuYMKN6MuqmgJE",
            "t2UmPyNoWSVUgyPzEXzFGN5GS96jMH2kreW",
            "t2MQWZJHxZF5zSw6LbZ3S7jqoLX1y6SWLHQ",
            "t2VUR1c1aFaTUo93uhi7rfFVRRZaT1aQYbv",
            "t2NgLU6QCJhCKgBsR5uX6R4ds82jymzMoMJ",
            "t2RorFwMUEb7NamvXFi3jCXitAdRoQtU1Hs",
            "t2FFtmwePBnYaRVRVg1wsoBPxDzGMLrz3Jv",
            "t2GH3734fKEhPo3NvvAZQazsFf3V51oR4c2",
            "t2Ev3twAmUmono3gM2Q6RsfhRiryy7TnX5E",
            "t2EmhhAjh6cLpyw6Yc9QEXvsjm7qdKpgFQP",
            "t2Gy5N7DYbEZmiHqm3m8Re25a8Bxu7e36ju",
            "t2LVSaxizciFWfc5gr1xccHXT115RSnQ13r",
            "t28zy3Qiq3FtMeB2PCEysF7R5TgW5UfZN1N",
            "t2FcN7o26gRCc8ZuSZcc7X7APPRqWQ5a3W2",
            "t27QTHP9qoi5HkiTqx4JV86MGG37aikK51s",
            "t2CwQ6H9GPT77nqRwkHCuVcyGvtbhxWHfAk",
            "t2HLUDaoimaaSpQhHnvbqpKg6Fi37rAo6cx",
            "t2Ebuq1FX7Qzi3ur1FnwsDMvfNBFjqVqDGX",
            "t2Bca3HbSbwgQp1ZhzheNvGfpwBoU6Syt8G",
            "t2EurfAqyJMsCyx6ujYecQSxrPPY7xxTqcB",
            "t2R1kJGeNhLpKx1dKNCnBUq1BkxBVJjQdcp",
            "t2M3x9koBJWJS1F9bGtWXTsVfr5pesWSTbR",
            "t2La4mEMruVTtBqhndS7zRvmi2WsqWUjPQz",
            "t29GwTHLXxYgF5k7SSj7XFaHB7JsocM9bDU",
            "t2Awpdv7yG2QFeHeq17J1qCSXRw1AM3mfmz",
            "t2BfotpLdNhhewRp9nXpBBYViBaq4y1Lnj5",
            "t2F4CH89prySyGZHUiPYJUjnZk9UPXgLBbf",
            "t2DNx1KzP8a2S3kZgAPngso9ptva5gE7Jbn",
            "t2Eb7orwhjGcu4wYwHBzN5BoXzroPGq3CoM",
            "t2BXYmM21WCdHiC1KiwQVHxaTvLQJpqXTvH",
            "t27Y6774dwAcCFvYrhDKTXgaxtUewAdZdtz",
            "t2JvmRjZnViBZXJJBekDygdvGTCRNWgFEK2",
            "t2PL5W7qy1DKNRPWECbaZ6gV9GEzMn8h97Z",
            "t2S1JaefdSNwaUexdr6ZtNJhqZS8uDGSNFg",
            "t2BTunj4VB44Q22crWpT1ykoBvNGFKMnD7N",
            "t2G7DkSoEUJGaEBH6erKsXemoHFqqTRaSiZ",
            "t2Ldg8Bc6AWDuESqPgUoumWfCYw3zqKF8s9",
            "t2Ft4QMMiJfKXVbhyGBrkwjnfn5ua73VuLo",
            "t26xLxd4Fabbotkc9gfFwpCVHoZG1W9rmN7",
            "t2DyghJMpK6rRKPEAL3DBKmCntUcj8bUiHg",
            "t2RSYhCsgw2AdBiUUyXBCkFf2xE9ddwyESD",
            "t26fv5NLiFYXMmfQnvqcJXcYnt5NY41eqrv",
            "t2Ppht55eXKC1BX7pfusJxZqbHnkp9oWbBW",
            "t2P4AWJ5C4ySU3KzfehAeppH2BV4Y87w34z",
            "t28zjDUH2Gkvt8Ytb8UrW7L6G5U1QMwJFM3",
            "t2JXDd9pumryTAXqDD98vDLS2ZLSQCNQrYZ",
            "t2BNuNGnGq49MZzr7SH8WtEE7sSwZ9n3bsz",
            "t2QumKdHZhkFD6ntrzJ9zJAga2QemEgqc9r",
            "t2UKz2L7V3C6GTeBPDXmQnwMyqKEbgMpuXg",
            "t2CyVugoafiDYpeSNd9DGZEng6Bpr4tqa3d",
            "t2GR9eEen8KUDjhQG1opC1aFt27zxdtufnF",
            "t2JKYuSRNupdHdTR91tqR4xsaU6friVJJgv",
            "t2D2yMZEM3K8ap6iLo3FX2g1Ch9coPSVq2R",
            "t2SeFu34eiE2rCPFpxrN8im6ZvcwMpdKnit",
            "t2KH46EXQy5wnZHDGVDA7Q13FdRkdQ3LUou",
            "t2UsTpuVqP6ZubtN8tQGPnh7Cqjjf1hoefd",
            "t2Dd119xiqDbF9QzWwYfnYWUPfqgnL1CNFu",
            "t29PjecMhv6EygD8W6smcMHAB8MSHQY3YnQ",
            "t2BDZpxgcMRzqgKbDBiXRXrvL3VwD7G8cLc",
            "t2MwiKqfCMdy7o96bXvbZ5aGCrRmVfVWVfA",
            "t2Vhkny4jNjy6ZD53jeQzsdgZiZyejwRsgY",
            "t2K3ouBrLAbYwZv6beoHjzfsE1AbYVa6PuE",
            "t2DskMSpWs8i9vK2PhNpi9Mu2qJSvEDi8UZ",
            "t2JB2Uz3eVWrxFhas1B1cSXLP22JHbRNYtL",
            "t2ArYKW1L8hRoCDK9odNmD4piRwFheErWL1",
            "t2K1zKGHrkibiFoYJ5GtfHe5xJecJPEvFwQ",
            "t2VnABknMprtMk8y5AdDCBr2R9QZnMhfqSm",
            "t2FbjEsP9eeQr5PmP7yC3fopPTuYS9E9VgN",
            "t2Sn2XUPZEnFcggB77jvxBqX6LcjdCzcJUs",
            "t2SEK3Tw5FYYUaeZcF5QemfeG3tiorrxNKp",
            "t2D78THpHVodnhiREjF22A3KRznor5pPnR1",
            "t2GyqFdkf6FoQTShEhLGsNrTxAWqmeq4pui",
            "t2HnNgFLznEqaokYq8PBV44uzRwAmJXQeKd",
            "t2PpHVStdHvWkzXsyuyPYQQq96ZRQu7ALpE",
            "t2FHbHM9rKKHZe74HRBNozwNdRsExug8tCw",
            "t29tM6DkMPSVp9R3g7UjZjvsobKhsbsRqFL",
            "t2K2KixLVJo19phPJMv9ApSiFmxQCSQUvc9",
            "t2AWJcGVUMWFC8A9KC3PL7qoCb1vxSzxbJP",
            "t26p8FyjHmhqZ6duzhRFLCQcExh1TuCD1sC",
            "t27x5n41uRNF3tJkb3Lg1CMomUjTNZwtUfm",
            "t2VhRQJ9xeVkVVk7ic21CtDePKmHnrDyF8Z",
            "t27hL1iAsTHBPWrdc1qYGSSTc3pTyBqohd4",
            "t2RqLYWG8Eo4hopDsn1m8GUoAWtjZQEPE9s",
            "t2V1osVDkcwYFL4PF9qG8t9Ez1XRVMAkAb6"
        };
        vCommunityFeeStartHeight = 1500;
        vCommunityFeeLastHeight = 1400000;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 780006;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 12020;
        nMaxTipAge = 24 * 60 * 60;
        //assert(consensus.hashGenesisBlock == uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a"));
        nPruneAfterHeight = 1000;
        newTimeRule = 159300;
        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;

        genesis = CreateGenesisBlock(
            1560969896,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("05ffd6ad016271ade20cfce093959c3addb2079629f9f123c52ef920caa316531af5af3f"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.
        vSeeds.push_back(CDNSSeedData("978b674532d58328c4da63ab138c476ffa2f8a8b2b5a023a668fd3a97eb7c48b.TZB", "testnetseed.ach.biz"));
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

                // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "t2FpKCWt95LAPVRed61YbBny9yz5nqexLGN",
            "t2RqJNenxiDjC5NiVo84xgfHcYuwsPcpCie",
            "t2MsHkAug2oEiqj4L5ZGZH1vHmdogTSb9km",
            "t2EwBFfC96DCiCAcJuEqGUbUes8rTNmaD6Q",
            "t2JqYXRoTsKb9r1rTLLwDs5jMXzsRBV317k",
            "t2RocidGU4ReKPK2uTPYfNFgeZEWDCd3jsj",
            "t2Mu8ToNiVow92PfETBk5Z6HWuAEG7RVXVD",
            "t2MSLT1n4eQ87QC2FAxMvuTZ84zDzEj7FhQ",
            "t2JZNFrWv1c4RqkCmDN9iRkPsG8xAZFdyGS",
            "t2AyjEVUCf5jthGHZjwfbztDBHQbztkJB5v",
            "t2Gs6dTYCzaFdHSeT91zaFLKmYzyqYY3NnP",
            "t2FXfNK7iQhTdMFcGUyrizqXQE5qbmPK6zc",
            "t2UqLwQ85pR1fdFMoUzXadXRB97JxP6vTWY",
            "t2BocGBq7iBXQP8UQiousNVwU8M6AqUtaRx",
            "t2VGGdXhspjF3iQvbWZW2zPNSDRSYauBcM3",
            "t2HTNHicoeEXxsX1wVhsqsX3LgzRq2pYgWH",
            "t2UiVSyM1vuvs6xP3157ytuYMKN6MuqmgJE",
            "t2UmPyNoWSVUgyPzEXzFGN5GS96jMH2kreW",
            "t2MQWZJHxZF5zSw6LbZ3S7jqoLX1y6SWLHQ",
            "t2VUR1c1aFaTUo93uhi7rfFVRRZaT1aQYbv",
            "t2NgLU6QCJhCKgBsR5uX6R4ds82jymzMoMJ",
            "t2RorFwMUEb7NamvXFi3jCXitAdRoQtU1Hs",
            "t2FFtmwePBnYaRVRVg1wsoBPxDzGMLrz3Jv",
            "t2GH3734fKEhPo3NvvAZQazsFf3V51oR4c2",
            "t2Ev3twAmUmono3gM2Q6RsfhRiryy7TnX5E",
            "t2EmhhAjh6cLpyw6Yc9QEXvsjm7qdKpgFQP",
            "t2Gy5N7DYbEZmiHqm3m8Re25a8Bxu7e36ju",
            "t2LVSaxizciFWfc5gr1xccHXT115RSnQ13r",
            "t28zy3Qiq3FtMeB2PCEysF7R5TgW5UfZN1N",
            "t2FcN7o26gRCc8ZuSZcc7X7APPRqWQ5a3W2",
            "t27QTHP9qoi5HkiTqx4JV86MGG37aikK51s",
            "t2CwQ6H9GPT77nqRwkHCuVcyGvtbhxWHfAk",
            "t2HLUDaoimaaSpQhHnvbqpKg6Fi37rAo6cx",
            "t2Ebuq1FX7Qzi3ur1FnwsDMvfNBFjqVqDGX",
            "t2Bca3HbSbwgQp1ZhzheNvGfpwBoU6Syt8G",
            "t2EurfAqyJMsCyx6ujYecQSxrPPY7xxTqcB",
            "t2R1kJGeNhLpKx1dKNCnBUq1BkxBVJjQdcp",
            "t2M3x9koBJWJS1F9bGtWXTsVfr5pesWSTbR",
            "t2La4mEMruVTtBqhndS7zRvmi2WsqWUjPQz",
            "t29GwTHLXxYgF5k7SSj7XFaHB7JsocM9bDU",
            "t2Awpdv7yG2QFeHeq17J1qCSXRw1AM3mfmz",
            "t2BfotpLdNhhewRp9nXpBBYViBaq4y1Lnj5",
            "t2F4CH89prySyGZHUiPYJUjnZk9UPXgLBbf",
            "t2DNx1KzP8a2S3kZgAPngso9ptva5gE7Jbn",
            "t2Eb7orwhjGcu4wYwHBzN5BoXzroPGq3CoM",
            "t2BXYmM21WCdHiC1KiwQVHxaTvLQJpqXTvH",
            "t27Y6774dwAcCFvYrhDKTXgaxtUewAdZdtz",
            "t2JvmRjZnViBZXJJBekDygdvGTCRNWgFEK2",
            "t2PL5W7qy1DKNRPWECbaZ6gV9GEzMn8h97Z",
            "t2S1JaefdSNwaUexdr6ZtNJhqZS8uDGSNFg",
            "t2BTunj4VB44Q22crWpT1ykoBvNGFKMnD7N",
            "t2G7DkSoEUJGaEBH6erKsXemoHFqqTRaSiZ",
            "t2Ldg8Bc6AWDuESqPgUoumWfCYw3zqKF8s9",
            "t2Ft4QMMiJfKXVbhyGBrkwjnfn5ua73VuLo",
            "t26xLxd4Fabbotkc9gfFwpCVHoZG1W9rmN7",
            "t2DyghJMpK6rRKPEAL3DBKmCntUcj8bUiHg",
            "t2RSYhCsgw2AdBiUUyXBCkFf2xE9ddwyESD",
            "t26fv5NLiFYXMmfQnvqcJXcYnt5NY41eqrv",
            "t2Ppht55eXKC1BX7pfusJxZqbHnkp9oWbBW",
            "t2P4AWJ5C4ySU3KzfehAeppH2BV4Y87w34z",
            "t28zjDUH2Gkvt8Ytb8UrW7L6G5U1QMwJFM3",
            "t2JXDd9pumryTAXqDD98vDLS2ZLSQCNQrYZ",
            "t2BNuNGnGq49MZzr7SH8WtEE7sSwZ9n3bsz",
            "t2QumKdHZhkFD6ntrzJ9zJAga2QemEgqc9r",
            "t2UKz2L7V3C6GTeBPDXmQnwMyqKEbgMpuXg",
            "t2CyVugoafiDYpeSNd9DGZEng6Bpr4tqa3d",
            "t2GR9eEen8KUDjhQG1opC1aFt27zxdtufnF",
            "t2JKYuSRNupdHdTR91tqR4xsaU6friVJJgv",
            "t2D2yMZEM3K8ap6iLo3FX2g1Ch9coPSVq2R",
            "t2SeFu34eiE2rCPFpxrN8im6ZvcwMpdKnit",
            "t2KH46EXQy5wnZHDGVDA7Q13FdRkdQ3LUou",
            "t2UsTpuVqP6ZubtN8tQGPnh7Cqjjf1hoefd",
            "t2Dd119xiqDbF9QzWwYfnYWUPfqgnL1CNFu",
            "t29PjecMhv6EygD8W6smcMHAB8MSHQY3YnQ",
            "t2BDZpxgcMRzqgKbDBiXRXrvL3VwD7G8cLc",
            "t2MwiKqfCMdy7o96bXvbZ5aGCrRmVfVWVfA",
            "t2Vhkny4jNjy6ZD53jeQzsdgZiZyejwRsgY",
            "t2K3ouBrLAbYwZv6beoHjzfsE1AbYVa6PuE",
            "t2DskMSpWs8i9vK2PhNpi9Mu2qJSvEDi8UZ",
            "t2JB2Uz3eVWrxFhas1B1cSXLP22JHbRNYtL",
            "t2ArYKW1L8hRoCDK9odNmD4piRwFheErWL1",
            "t2K1zKGHrkibiFoYJ5GtfHe5xJecJPEvFwQ",
            "t2VnABknMprtMk8y5AdDCBr2R9QZnMhfqSm",
            "t2FbjEsP9eeQr5PmP7yC3fopPTuYS9E9VgN",
            "t2Sn2XUPZEnFcggB77jvxBqX6LcjdCzcJUs",
            "t2SEK3Tw5FYYUaeZcF5QemfeG3tiorrxNKp",
            "t2D78THpHVodnhiREjF22A3KRznor5pPnR1",
            "t2GyqFdkf6FoQTShEhLGsNrTxAWqmeq4pui",
            "t2HnNgFLznEqaokYq8PBV44uzRwAmJXQeKd",
            "t2PpHVStdHvWkzXsyuyPYQQq96ZRQu7ALpE",
            "t2FHbHM9rKKHZe74HRBNozwNdRsExug8tCw",
            "t29tM6DkMPSVp9R3g7UjZjvsobKhsbsRqFL",
            "t2K2KixLVJo19phPJMv9ApSiFmxQCSQUvc9",
            "t2AWJcGVUMWFC8A9KC3PL7qoCb1vxSzxbJP",
            "t26p8FyjHmhqZ6duzhRFLCQcExh1TuCD1sC",
            "t27x5n41uRNF3tJkb3Lg1CMomUjTNZwtUfm",
            "t2VhRQJ9xeVkVVk7ic21CtDePKmHnrDyF8Z",
            "t27hL1iAsTHBPWrdc1qYGSSTc3pTyBqohd4",
            "t2RqLYWG8Eo4hopDsn1m8GUoAWtjZQEPE9s",
            "t2V1osVDkcwYFL4PF9qG8t9Ez1XRVMAkAb6"
        };
        vCommunityFeeStartHeight = 200;
        vCommunityFeeLastHeight = 1400000;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

// Index variable i ranges from 0 - (vCommunityFeeAddress.size()-1)
std::string CChainParams::GetCommunityFeeAddressAtHeight(int nHeight) const {
    int maxHeight = GetLastCommunityFeeBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vCommunityFeeAddress.size()) / vCommunityFeeAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vCommunityFeeAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetCommunityFeeScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= GetLastCommunityFeeBlockHeight());

    CTxDestination address = DecodeDestination(GetCommunityFeeAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetCommunityFeeAddressAtIndex(int i) const {
    assert(i >= 0 && i < vCommunityFeeAddress.size());
    return vCommunityFeeAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blockheight >= params.eh_epoch_2_start() && blockheight > params.eh_epoch_1_end()){
        ehparams[0] = params.eh_epoch_2_params();
        return 1;
    }
    if(blockheight < params.eh_epoch_2_start()){
        ehparams[0] = params.eh_epoch_1_params();
        return 1;
    }
    ehparams[0] = params.eh_epoch_2_params();
    ehparams[1] = params.eh_epoch_1_params();
    return 2;
}

bool checkEHParamaters(int solSize, int height, const CChainParams& params) {
    // Block will be validated prior to mining, and will have a zero length
    // equihash solution. These need to be let through.
    if (height == 0) {
        return true;
    }

    //allocate on-stack space for parameters list
    EHparameters ehparams[MAX_EH_PARAM_LIST_LEN];
    int listlength = validEHparameterList(ehparams, height, params);
    for(int i = 0; i < listlength; i++){
        LogPrint("pow", "checkEHParamaters height: %d n:%d k:%d solsize: %d \n", 
            height, ehparams[i].n, ehparams[i].k, ehparams[i].nSolSize);
        if (ehparams[i].nSolSize == solSize)
            return true;
    }

    return false;
}
