-- Implementation of the Public Verifiable Secret Scheme based on Berry Schoenmakers's paper:
--
--	<http://www.win.tue.nl/~berry/papers/crypto99.pdf>
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PVSS
    (
    -- * Simple alias
      Threshold
    , ShareId
    , ExtraGen
    , Point
    , Scalar
    , Secret
    , KeyPair(..)
    , DhSecret(..)
    -- * Types
    , Escrow(..)
    , Commitment
    , EncryptedShare(..)
    , DecryptedShare(..)
    -- * method
    , escrow
    , escrowWith
    , escrowNew
    , createCommitments
    , sharesCreate
    , shareCreate
    , shareDecrypt
    , verifyEncryptedShare
    , verifyDecryptedShare
    , verifySecret
    , getValidRecoveryShares
    , recover
    , secretToDhSecret
    -- * temporary export to get testing
    , keyPairGenerate
    ) where

import           Control.Monad
import           Control.DeepSeq

import           GHC.Generics

import           Data.ByteString (ByteString)
import           Data.List (foldl')
import           Data.Binary
import           Data.Binary.Get (getWord32le)
import           Data.Binary.Put (putWord32le)

import           Crypto.Random
import           Crypto.PVSS.Polynomial (Polynomial(..))
import qualified Crypto.PVSS.Polynomial as Polynomial
import qualified Crypto.PVSS.DLEQ as DLEQ
import           Crypto.PVSS.ECC

newtype Commitment = Commitment { unCommitment :: Point }
    deriving (Show,Eq,NFData,Binary)

-- | The number of shares needed to reconstitute the secret
type Threshold = Integer

-- | The number of parties in the scheme
type Participants = Integer

-- | The ID associated with a share
type ShareId = Integer

-- | Extra generator
newtype ExtraGen = ExtraGen Point
    deriving (Show,Eq,NFData,Binary)

-- | Secret
newtype Secret = Secret Point
    deriving (Show,Eq,NFData,Binary)

-- | Transform a secret into a usable random value
secretToDhSecret :: Secret -> DhSecret
secretToDhSecret (Secret p) = pointToDhSecret p

-- | An encrypted share associated to a party's key.
data EncryptedShare = EncryptedShare
    { shareID           :: !ShareId
    , shareEncryptedVal :: !Point      -- ^ encrypted by participant public key
    , shareValidProof   :: !DLEQ.Proof -- ^ proof it's a valid share
    } deriving (Show,Eq,Generic)

instance NFData EncryptedShare
instance Binary EncryptedShare where
    get = EncryptedShare <$> (fromIntegral <$> getWord32le) <*> get <*> get
    put (EncryptedShare sid val proof) = putWord32le (fromIntegral sid) >> put val >> put proof

-- | An decrypted share decrypted by a party's key and
data DecryptedShare = DecryptedShare
    { decryptedShareID    :: !ShareId
    , shareDecryptedVal   :: !Point      -- ^ decrypted share
    , decryptedValidProof :: !DLEQ.Proof -- ^ proof the decryption is valid
    } deriving (Show,Eq,Generic)

instance NFData DecryptedShare
instance Binary DecryptedShare where
    get = DecryptedShare <$> (fromIntegral <$> getWord32le) <*> get <*> get
    put (DecryptedShare sid val proof) = putWord32le (fromIntegral sid) >> put val >> put proof

data Escrow = Escrow
    { escrowExtraGen   :: !ExtraGen
    , escrowPolynomial :: !Polynomial
    , escrowSecret     :: !Secret
    , escrowProof      :: !DLEQ.Proof
    } deriving (Show,Eq,Generic)

instance NFData Escrow

-- | Prepare a new escrowing context
--
-- The only needed parameter is the threshold
-- do not re-use an escrow context for different context.
escrowNew :: MonadRandom randomly
          => Threshold
          -> randomly Escrow
escrowNew threshold = do
    poly <- Polynomial.generate (fromIntegral threshold)
    gen  <- pointFromSecret <$> keyGenerate

    let secret = Polynomial.atZero poly
        gS     = pointFromSecret secret
    challenge <- keyGenerate
    let dleq  = DLEQ.DLEQ { DLEQ.dleq_g1 = curveGenerator, DLEQ.dleq_h1 = gS, DLEQ.dleq_g2 = gen, DLEQ.dleq_h2 = gen .* secret }
        proof = DLEQ.generate challenge secret dleq

    return $ Escrow
        { escrowExtraGen   = ExtraGen gen
        , escrowPolynomial = poly
        , escrowSecret     = Secret gS
        , escrowProof      = proof
        }

-- | Prepare a secret into public encrypted shares for distributions using the PVSS scheme
--
-- returns:
--  * the encrypted secret which is locked symettrically to the DH-secret (g^random)
--  * the list of public commitments (Cj) to the scheme
--  * The encrypted shares that should be distributed to each partipants.
escrow :: MonadRandom randomly
       => Threshold        -- ^ PVSS scheme configuration n/t threshold
       -> [Point]          -- ^ Participants public keys
       -> randomly (ExtraGen, Secret, DLEQ.Proof, [Commitment], [EncryptedShare])
escrow t pubs = do
    e <- escrowNew t
    (commitments, eshares) <- escrowWith e pubs
    return (escrowExtraGen e, escrowSecret e, escrowProof e, commitments, eshares)

-- | Escrow with a given polynomial
escrowWith :: MonadRandom randomly
           => Escrow
           -> [Point]    -- ^ Participants public keys
           -> randomly ([Commitment], [EncryptedShare])
escrowWith escrow pubs = do
    let commitments = createCommitments escrow

    -- create the encrypted shares Yi + proof
    encryptedShares <- sharesCreate escrow commitments pubs

    return (commitments, encryptedShares)

createCommitments :: Escrow -> [Commitment]
createCommitments escrow =
    -- create commitments Cj = g ^ aj
    map (\c -> Commitment (g .* c)) polyCoeffs
  where
    Polynomial polyCoeffs = escrowPolynomial escrow
    ExtraGen g = escrowExtraGen escrow

sharesCreate :: MonadRandom randomly
             => Escrow
             -> [Commitment]
             -> [Point]
             -> randomly [EncryptedShare]
sharesCreate escrow commitments pubs = forM (zip [1..] pubs) $ uncurry (shareCreate escrow commitments)

-- | Create a specific share given a public key and the overall parameters
shareCreate :: MonadRandom randomly
            => Escrow
            -> [Commitment]
            -> ShareId
            -> Point
            -> randomly EncryptedShare
shareCreate e commitments shareId pub = do
    let pEvaled_i = Polynomial.evaluate poly (keyFromNum $ shareId)
        yi        = pub .* pEvaled_i
        xi        = g .* pEvaled_i -- createXi shareId commitments
    challenge <- keyGenerate
    let dleq  = DLEQ.DLEQ { DLEQ.dleq_g1 = g, DLEQ.dleq_h1 = xi, DLEQ.dleq_g2 = pub, DLEQ.dleq_h2 = yi }
        proof = DLEQ.generate challenge pEvaled_i dleq

    return $ EncryptedShare shareId yi proof
  where
    ExtraGen g = escrowExtraGen e
    poly = escrowPolynomial e

-- | Decrypt an Encrypted share using the party's key pair.
-- Doesn't verify if an encrypted share is valid, for this
-- you need to use 'verifyEncryptedShare'
--
-- 1) compute Si = Yi ^ (1/xi) = G^(p(i))
-- 2) create a proof of the valid decryption
shareDecrypt :: MonadRandom randomly
             => KeyPair
             -> EncryptedShare
             -> randomly DecryptedShare
shareDecrypt (KeyPair xi yi) (EncryptedShare sid _Yi _) = do
    challenge <- keyGenerate
    let dleq  = DLEQ.DLEQ curveGenerator yi si _Yi
        proof = DLEQ.generate challenge xi dleq
    return $ DecryptedShare sid si proof
  where xiInv = keyInverse xi
        si    = _Yi .* xiInv

-- | Verify an encrypted share
--
-- anyone can do that given the extra generator and the commitments
verifyEncryptedShare :: ExtraGen
                     -> [Commitment]
                     -> (EncryptedShare, Point) -- ^ the encrypted and the associated public key
                     -> Bool
verifyEncryptedShare (ExtraGen g) commitments (share,pub) =
    DLEQ.verify dleq (shareValidProof share)
  where dleq = DLEQ.DLEQ
                { DLEQ.dleq_g1 = g
                , DLEQ.dleq_h1 = xi
                , DLEQ.dleq_g2 = pub
                , DLEQ.dleq_h2 = shareEncryptedVal share
                }
        xi = createXi (fromIntegral $ shareID share) commitments

-- | Verify a decrypted share against the public key and the encrypted share
verifyDecryptedShare :: (EncryptedShare, Point, DecryptedShare)
                     -> Bool
verifyDecryptedShare (eshare,pub,share) =
    DLEQ.verify dleq (decryptedValidProof share)
  where dleq = DLEQ.DLEQ curveGenerator pub (shareDecryptedVal share) (shareEncryptedVal eshare)

-- | Verify that a secret recovered is the one escrow
verifySecret :: ExtraGen
             -> [Commitment]
             -> Secret
             -> DLEQ.Proof
             -> Bool
verifySecret (ExtraGen gen) commitments (Secret secret) proof =
    DLEQ.verify dleq proof
  where dleq = DLEQ.DLEQ
            { DLEQ.dleq_g1 = curveGenerator
            , DLEQ.dleq_h1 = secret
            , DLEQ.dleq_g2 = gen
            , DLEQ.dleq_h2 = unCommitment (commitments !! 0)
            }

-- | Recover the DhSecret used
--
-- Need to pass the correct amount of shares (threshold),
-- preferably from a 'getValidRecoveryShares' call
recover :: [DecryptedShare]
        -> Secret
recover shares =
    Secret $ foldl' interpolate pointIdentity (zip shares [0..])
  where
    t = fromIntegral $ length shares

    interpolate :: Point -> (DecryptedShare, ShareId) -> Point
    interpolate !result (share, sid) = result .+ (shareDecryptedVal share .* value)
      where
        value = calc 0 (keyFromNum 1)
        calc :: Integer -> Scalar -> Scalar
        calc !j acc
            | j == t       = acc
            | j == sid     = calc (j+1) acc
            | otherwise    =
                let sj   = decryptedShareID (shares !! fromIntegral j)
                    si   = decryptedShareID (shares !! fromIntegral sid)
                    dinv = keyInverse (keyFromNum sj #- keyFromNum si)
                    e    = keyFromNum sj #* dinv
                 in calc (j+1) (acc #* e)

-- | Get #Threshold decrypted share that are deemed valid
getValidRecoveryShares :: Threshold
                       -> [(EncryptedShare, Point, DecryptedShare)]
                       -> [DecryptedShare]
getValidRecoveryShares threshold shares =
    map thd . take (fromIntegral threshold) . filter verifyDecryptedShare $ shares
  where thd (_,_,ds) = ds

createXi :: ShareId      -- ^ index i
         -> [Commitment] -- ^ all commitments
         -> Point
createXi i commitments =
    let es  = [ (keyFromNum (fromIntegral i) #^ j) | j <- [0..] ]
     in foldl' (.+) pointIdentity $ zipWith (.*) (map unCommitment commitments) es
