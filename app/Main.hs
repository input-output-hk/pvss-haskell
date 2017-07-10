{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
module Main where

import           System.Environment
import           Control.Monad
import           Control.Exception
import           Control.DeepSeq
import qualified Crypto.PVSS as PVSS
import qualified Crypto.SCRAPE as SCRAPE
import           Data.List
import           Time.Types
import           Time.System
import           Data.Hourglass (timeDiffP)
import           Text.Printf (printf)

#ifdef VERSION_mcl
import qualified Crypto.SCRAPE.BDS as SCRAPE_BDS
import qualified Data.Vector as V
#endif

showTimeDiff :: (Seconds, NanoSeconds) -> String
showTimeDiff (Seconds s, NanoSeconds n) =
    if s > 10
        then printf "%d.%03d seconds" s (n `div` 1000000)
        else printf "%d.%06d seconds" s (n `div` 1000)

timing :: NFData t => IO t -> IO (t, (Seconds, NanoSeconds))
timing f = do
    t1 <- timeCurrentP
    a  <- f
    t2 <- a `deepseq` timeCurrentP
    return (a, t2 `timeDiffP` t1)

timingP :: NFData b => String -> IO b -> IO b
timingP n f = do
    (!a, t) <- timing f
    putStrLn (n ++ ": " ++ showTimeDiff t)
    return a

timingPureP :: NFData b => String -> b -> IO b
timingPureP n f = do
    t1 <- timeCurrentP
    !a <- evaluate f
    t2 <- a `deepseq` timeCurrentP
    putStrLn (n ++ ": " ++ showTimeDiff (t2 `timeDiffP` t1))
    return a

chunk :: Int -> [t] -> [[t]]
chunk _ [] = []
chunk n l =
    let (l1,l2) = splitAt n l
     in l1 : chunk n l2

go :: PVSS.Threshold -> Int -> IO ()
go t n = do
    participants <- replicateM n $ PVSS.keyPairGenerate

    (e, commitments, eshares) <-
        timingP "escrow" $ do
            !xe <- {-timingP "escrow-new" $-} PVSS.escrowNew t

            !xcommitments <- {-timingP "commitments" $-} return $ PVSS.createCommitments xe

            !xesharesChunks <- {-timingP "shares" $-} forM (chunk 200 $ zip [1..] (map PVSS.toPublicKey participants)) $ \c ->
                {-timingP ("  chunk-" ++ show (fst $ head c)) $ -}forM c $ uncurry (PVSS.shareCreate xe xcommitments)
            let eshares = mconcat xesharesChunks
            return (xe, xcommitments, eshares)


    !validated <- timingP "validating" $ forM (chunk 200 $ zip eshares (map PVSS.toPublicKey participants)) $ \c ->
        {-timingP ("  vchunk") $ -} forM c $ return . PVSS.verifyEncryptedShare (PVSS.escrowExtraGen e) commitments
    putStrLn (show $ and $ concat validated)

    !decryptedShares <- timingP "decrypting" $ mapM (\(kp,eshare) -> do
            p <- PVSS.shareDecrypt kp eshare
            return $! p
        ) (zip participants eshares)

    !verifiedShares <- timingPureP "verifying" $
        PVSS.getValidRecoveryShares t (zip3 eshares (map PVSS.toPublicKey participants) decryptedShares)
    putStrLn (show $ t == fromIntegral (length verifiedShares))

    recovered <- timingPureP "recovering" $ PVSS.recover $ take (fromIntegral t+1) $ decryptedShares
    putStrLn $ show $ PVSS.escrowSecret e
    putStrLn $ show recovered

goScrapeDDH :: SCRAPE.Threshold -> Int -> IO ()
goScrapeDDH t n = do
    keypairParticipants <- {-timingP "keypair"-} (replicateM n $ PVSS.keyPairGenerate)
    () <- deepseq keypairParticipants (return ())
    let participantsPublicKeys = map PVSS.toPublicKey keypairParticipants
        participants           =  SCRAPE.Participants participantsPublicKeys

    (extraGen, sec, esis, commitments, _proof, parallelProofs) <- timingP "escrow" $ SCRAPE.escrow t participants

    !_validated <- timingP "validating" $ SCRAPE.verifyEncryptedShares extraGen t commitments parallelProofs esis participants
    --putStrLn ("encrypted validated: " ++ show validated)

    !decryptedShares <- timingP "decrypting" $ mapM (\(kp,eshare) -> do
            p <- SCRAPE.shareDecrypt kp eshare
            return $! p
        ) (zip keypairParticipants esis)

    let select = take $ fromIntegral t
    !v <- timingPureP "verifying-decrypted" $
        and $ map (SCRAPE.verifyDecryptedShare) $ select $ zip3 esis participantsPublicKeys decryptedShares
    putStrLn $ show v

    recovered <- timingPureP "recovering" $ SCRAPE.recover $ zip [1..] $ select decryptedShares
    putStrLn $ "secret   : " ++ show sec
    putStrLn $ "recovered: " ++ show recovered

#ifdef VERSION_mcl
goScrapeBDS :: Int -> Int -> IO ()
goScrapeBDS t n = do
  (dp, parties) <- timingP "setup" $ SCRAPE_BDS.setup n

  (secret, encryptedShares, commitments) <- timingP "distribution" $
    SCRAPE_BDS.distribution dp parties t

  timingP "verification" $
    SCRAPE_BDS.verification dp t parties encryptedShares commitments

  recoveredSecret <- timingP "reconstruction" $
    SCRAPE_BDS.reconstruction dp (V.take t) parties encryptedShares commitments

  unless (secret == recoveredSecret) $ do
    fail $ "secret and recoveredSecret do not match: secret = "
      ++ show secret ++ ", recoveredSecret = " ++ show recoveredSecret

  putStrLn $ "secret: " ++ show recoveredSecret
#endif

main :: IO ()
main = do
    args <- getArgs
    case args of
#ifdef VERSION_mcl
        ["scrape-bds", tS, nS] -> goScrapeBDS (read tS) (read nS)
#endif
        ["scrape-ddh", tS, nS] -> goScrapeDDH (read tS) (read nS)
        ["pvss", tS, nS]       -> go (read tS) (read nS)
        _                      -> error $ "error: pvss [" ++ scrapeVersions ++ "] <threshold> <number>"
  where
    scrapeVersions = intercalate "|"
      [ "scrape-ddh"
#ifdef VERSION_mcl
      , "scrape-bds"
#endif
      , "pvss"
      ]
