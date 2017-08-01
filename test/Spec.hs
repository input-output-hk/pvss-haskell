module Main where

import           Control.Monad
import           Crypto.Random
import qualified Crypto.PVSS as PVSS
import qualified Crypto.SCRAPE as SCRAPE
import           Test.Tasty
import           Test.Tasty.QuickCheck

newtype Threshold = Threshold PVSS.Threshold
    deriving (Show,Eq)

newtype Participants = Participants Integer
    deriving (Show,Eq)

data KofN = KofN PVSS.Threshold Integer
    deriving (Show,Eq)

instance Arbitrary Threshold where
    arbitrary = Threshold <$> choose (1,5)
instance Arbitrary Participants where
    arbitrary = Participants <$> choose (2,10)

instance Arbitrary KofN where
    arbitrary = do
        n <- choose (3,20)
        t <- choose (1,8)
        pure $ if t >= n then KofN t (t+1)
                         else KofN t n

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

-----------------------------------------------
-- SCRAPE test

scrapeEncryptVerify :: KofN -> ChaChaDRG -> Property
scrapeEncryptVerify (KofN threshold nOrig) rng =
    let (r, _) = withDRG rng3 $ SCRAPE.verifyEncryptedShares egen threshold commitments proofs eshares participants
     in r === True
  where
    n :: Integer
    n = max (threshold) nOrig

    (participantAll, rng2) = withDRG rng $ replicateM (fromIntegral n) PVSS.keyPairGenerate
    participants = SCRAPE.Participants $ map toPk participantAll

    ((egen, sec, eshares, commitments, proof, proofs), rng3) = withDRG rng2 $
        SCRAPE.escrow threshold participants

scrapeDecryptVerify :: KofN -> ChaChaDRG -> Property
scrapeDecryptVerify (KofN threshold nOrig) rng =
        map (SCRAPE.verifyDecryptedShare) (zip3 eshares (map toPk participantAll) decryptedShares)
    === map (const True) eshares
  where
    n :: Integer
    n = max (threshold) nOrig

    (participantAll, rng2) = withDRG rng $ replicateM (fromIntegral n) SCRAPE.keyPairGenerate
    participants = SCRAPE.Participants $ map toPk participantAll

    ((egen, sec, eshares, commitments, proof, proofs), rng3) = withDRG rng2 $
        SCRAPE.escrow threshold participants
    (decryptedShares, _) = withDRG rng3 $ do
        mapM (\(kp,eshare) -> SCRAPE.shareDecrypt kp eshare) (zip participantAll eshares)

scrapeSecretVerify :: KofN -> ChaChaDRG -> Property
scrapeSecretVerify (KofN threshold nOrig) rng =
    SCRAPE.verifySecret egen threshold commitments sec secProof === True
  where
    n :: Integer
    n = max (threshold) nOrig

    (participantAll, rng2) = withDRG rng $ replicateM (fromIntegral n) SCRAPE.keyPairGenerate
    participants = SCRAPE.Participants $ map toPk participantAll

    ((egen, sec, eshares, commitments, secProof, proofs), rng3) = withDRG rng2 $
        SCRAPE.escrow threshold participants

scrapeRecovery :: KofN -> ChaChaDRG -> Property
scrapeRecovery (KofN threshold nOrig) rng =

    let recovered = SCRAPE.recover $ take (fromIntegral (threshold+1)) $ zip [1..] decryptedShares
     in recovered === sec

  where
    n :: Integer
    n = max (threshold) nOrig

    (participants, rng2) = withDRG rng $ replicateM (fromIntegral n) SCRAPE.keyPairGenerate

    ((egen, sec, eshares, commitments, proof, proofs), rng3) = withDRG rng2 $
        SCRAPE.escrow threshold (SCRAPE.Participants $ map toPk participants)

    (decryptedShares, _) = withDRG rng3 $ do
        mapM (\(kp,eshare) -> SCRAPE.shareDecrypt kp eshare) (zip participants eshares)

main :: IO ()
main = defaultMain $ testGroup "PVSS"
    [ testGroup "schoenmaker"
        [ testProperty "encrypted-verified" testEncryptVerify
        , testProperty "decrypted-verified" testDecryptVerify
        , testProperty "secret-verified" testSecretVerify
        , testProperty "recovery" testRecovery ]
    , testGroup "scrape"
        [ testProperty "encrypted-verified" scrapeEncryptVerify
        , testProperty "decrypted-verified" scrapeDecryptVerify
        , testProperty "secret-verified" scrapeSecretVerify
        , testProperty "recovery" scrapeRecovery ]
    ]
