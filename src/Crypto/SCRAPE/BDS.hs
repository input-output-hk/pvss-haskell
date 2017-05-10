-- Implementation of SCRAPE - in BDS
--
--	<http://eprint.iacr.org/2017/216>
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.SCRAPE.BDS
  ( DP(..)
  , PubKey(..)
  , PrivKey(..)
  , Party(..)
  , setup
  , distribution
  , verification
  , reconstruction
  ) where

import Control.DeepSeq
import Control.Monad
import Crypto.Number.Generate
import Crypto.Random
import MCL.Curves.Fp254BNb
import qualified Data.Foldable as F
import qualified Data.Vector as V

----------------------------------------
-- Data structures

data DP = DP
  { g1  :: !G1
  , g2  :: !G2
  , g2' :: !G2
  } deriving (Eq, Show)

instance NFData DP where
  rnf DP{..} = rnf g1 `seq` rnf g2 `seq` rnf g2' `seq` ()

newtype PubKey = PubKey { unPubKey :: G1 }
  deriving (Eq, Show, NFData)

newtype PrivKey = PrivKey { unPrivKey :: Fr }
  deriving (Eq, Show, NFData)

data Party = Party
  { pubKey  :: !PubKey
  , privKey :: !PrivKey
  } deriving (Eq, Show)

instance NFData Party where
  rnf Party{..} = rnf pubKey `seq` rnf privKey `seq` ()

----------------------------------------
-- Reed-Solomon codes

newtype Polynomial = Polynomial (V.Vector Fr)
  deriving (Eq, Show)

randomPolynomial :: MonadRandom m => Int -> m Polynomial
randomPolynomial n
  | n >= 0    = Polynomial <$> V.replicateM n randomFr
  | otherwise = error $ "negative degree of a polynomial: " ++ show n

evalPolynomial :: Fr -> Polynomial -> Fr
evalPolynomial a (Polynomial p) = snd $ V.foldl' f (1, 0) p
  where
    f :: (Fr, Fr) -> Fr -> (Fr, Fr)
    f (!x, !result) coeff = (a*x, coeff*x + result)

rsCode :: Int -> Polynomial -> V.Vector Fr
rsCode n poly = V.generate n $ \j -> let i = j + 1 in
  evalPolynomial (fromIntegral i) poly

rsDualCode :: Int -> Polynomial -> V.Vector Fr
rsDualCode n poly = V.generate n $ \k -> let i = k + 1 in
  coeff i * evalPolynomial (fromIntegral i) poly
  where
    coeff :: Int -> Fr
    coeff i = go n 1
      where
        go :: Int -> Fr -> Fr
        go j !acc
          | j == 0    = acc
          | j == i    = go (j - 1) $ acc
          | otherwise = go (j - 1) $ acc * recip (fromIntegral $ i - j)

----------------------------------------
-- Misc

randomFr :: MonadRandom m => m Fr
randomFr = mkFr <$> generateMax fr_modulus

encryptShare :: PubKey -> Fr -> G1
encryptShare (PubKey g) m = g `g1_powFr` m

decryptShare :: PrivKey -> G1 -> G1
decryptShare (PrivKey k) g = g `g1_powFr` recip k

verifyCheck :: Monad m => String -> V.Vector Bool -> m ()
verifyCheck f check = (`V.imapM_` check) $ \i success -> unless success $ do
  fail $ f ++ ": share " ++ show i ++ " is invalid"

----------------------------------------
-- Protocol phases

setup
  :: MonadRandom m
  => Int
  -> m (DP, V.Vector Party)
setup n = do
  parties <- V.replicateM n $ do
    privKey@(PrivKey k) <- PrivKey <$> randomFr
    let pubKey = PubKey $ g1 `g1_powFr` k
    return Party{..}
  return (DP{..}, parties)
  where
    g1  = mapToG1 1
    g2  = mapToG2 2
    g2' = mapToG2 3

distribution
  :: MonadRandom m
  => DP
  -> V.Vector Party
  -> Int
  -> m (GT, V.Vector G1, V.Vector G2)
distribution DP{..} parties t = do
  poly <- randomPolynomial t
  let s = evalPolynomial 0 poly
      secret = pairing g1 g2' `gt_powFr` s

  let shares = rsCode (V.length parties) poly

      encryptedShares = (`V.imap` parties) $ \i party ->
        encryptShare (pubKey party) $ shares V.! i

      commitments = V.map (g2 `g2_powFr`) shares

  return (secret, encryptedShares, commitments)

verification
  :: MonadRandom m
  => DP
  -> Int
  -> V.Vector Party
  -> V.Vector G1
  -> V.Vector G2
  -> m ()
verification DP{..} t parties encryptedShares commitments = do
  let sharesCheck = (`V.imap` parties) $ \i p ->
        let e1 = pairing (encryptedShares V.! i) g2
            e2 = pairing (unPubKey $ pubKey p) (commitments V.! i)
        in e1 == e2

  verifyCheck "verification" sharesCheck

  let n = V.length parties
  poly <- randomPolynomial $ n - t - 1
  let code = rsDualCode n poly
      result = F.fold $ V.imap (\i v -> v `g2_powFr` (code V.! i)) commitments

  unless (result == g2_zero) $ do
    fail $ "verification: shares are invalid, " ++ show result ++ " is not 0"

reconstruction
  :: MonadRandom m
  => DP
  -> (forall t. V.Vector t -> V.Vector t)
  -> V.Vector Party
  -> V.Vector G1
  -> V.Vector G2
  -> m GT
reconstruction DP{..} select allParties allEncryptedShares allCommitments = do
  let shares = V.imap (\i -> decryptShare (privKey $ parties V.! i)) encryptedShares
      sharesCheck = (`V.imap` shares) $ \i share ->
        pairing share g2 == pairing g1 (commitments V.! i)

  verifyCheck "reconstruction" sharesCheck

  let result = F.fold $ V.imap (\i share -> share `g1_powFr` coeff i) shares
  return $ pairing result g2'
  where
    ids             = select $ V.enumFromTo 1 (V.length allParties)
    parties         = select allParties
    encryptedShares = select allEncryptedShares
    commitments     = select allCommitments

    coeff :: Int -> Fr
    coeff i = go 0 1
      where
        t = V.length ids

        go :: Int -> Fr -> Fr
        go j !acc
          | j == t    = acc
          | j == i    = go (j + 1) $ acc
          | otherwise =
            let id_i = ids V.! i
                id_j = ids V.! j
            in go (j + 1) $ acc * fromIntegral id_j / fromIntegral (id_j - id_i)
