module Main where

import           Control.Monad
import           Crypto.Random
import qualified Crypto.PVSS as PVSS
import           Test.Tasty
import           Test.Tasty.QuickCheck

newtype Threshold = Threshold PVSS.Threshold
    deriving (Show,Eq)

newtype Participants = Participants Integer
    deriving (Show,Eq)

instance Arbitrary Threshold where
    arbitrary = Threshold <$> choose (2,5)
instance Arbitrary Participants where
    arbitrary = Participants <$> choose (3,10)
instance Show ChaChaDRG where
    show _ = "chachaDRG"
instance Arbitrary ChaChaDRG where
    arbitrary = arbitrary >>= \n -> return $ drgNewTest (0,0,0,0,n)

toPk :: PVSS.KeyPair -> PVSS.PublicKey
toPk = PVSS.toPublicKey

testEncryptVerify :: Threshold -> Participants -> ChaChaDRG -> Property
testEncryptVerify (Threshold threshold) (Participants nOrig) rng =
    map (PVSS.verifyEncryptedShare egen commitments) (zip eshares (map toPk participants)) === map (const True) eshares
  where
    n :: Integer
    n = max (threshold) nOrig

    (participants, rng2) = withDRG rng $ replicateM (fromIntegral n) PVSS.keyPairGenerate

    ((egen, sec, _, commitments, eshares), rng3) = withDRG rng2 $
        PVSS.escrow threshold (map toPk participants)

testDecryptVerify :: Threshold -> Participants -> ChaChaDRG -> Property
testDecryptVerify (Threshold threshold) (Participants nOrig) rng =
        map (PVSS.verifyDecryptedShare) (zip3 eshares (map toPk participants) decryptedShares)
    === map (const True) eshares
  where
    n :: Integer
    n = max (threshold) nOrig

    (participants, rng2) = withDRG rng $ replicateM (fromIntegral n) PVSS.keyPairGenerate

    ((egen, sec, _, commitments, eshares), rng3) = withDRG rng2 $
        PVSS.escrow threshold (map toPk participants)

    (decryptedShares, _) = withDRG rng3 $ do
        mapM (\(kp,eshare) -> PVSS.shareDecrypt kp eshare) (zip participants eshares)

testSecretVerify :: Threshold -> Participants -> ChaChaDRG -> Property
testSecretVerify (Threshold threshold) (Participants nOrig) rng =
    PVSS.verifySecret egen commitments sec secProof === True
  where
    n :: Integer
    n = max (threshold) nOrig

    (participants, rng2) = withDRG rng $ replicateM (fromIntegral n) PVSS.keyPairGenerate

    ((egen, sec, secProof, commitments, _), rng3) = withDRG rng2 $
        PVSS.escrow threshold (map toPk participants)

testRecovery :: Threshold -> Participants -> ChaChaDRG -> Property
testRecovery (Threshold threshold) (Participants nOrig) rng =

    let recovered = PVSS.recover $ take (fromIntegral (threshold+1)) $ decryptedShares
     in recovered === sec

  where
    n :: Integer
    n = max (threshold) nOrig

    (participants, rng2) = withDRG rng $ replicateM (fromIntegral n) PVSS.keyPairGenerate

    ((egen, sec, _, commitments, eshares), rng3) = withDRG rng2 $
        PVSS.escrow threshold (map toPk participants)

    (decryptedShares, _) = withDRG rng3 $ do
        mapM (\(kp,eshare) -> PVSS.shareDecrypt kp eshare) (zip participants eshares)

main :: IO ()
main = defaultMain $ testGroup "PVSS"
    [ testProperty "encrypted-verified" testEncryptVerify
    , testProperty "decrypted-verified" testDecryptVerify
    , testProperty "secret-verified" testSecretVerify
    , testProperty "recovery" testRecovery ]
