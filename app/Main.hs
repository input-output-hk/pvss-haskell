{-# LANGUAGE BangPatterns #-}
module Main where

import           System.Environment
import           Control.Monad
import           Control.Exception
import           Control.DeepSeq
import qualified Crypto.PVSS as PVSS
import qualified Crypto.SCRAPE as SCRAPE
import           Time.Types
import           Time.System
import           Data.Hourglass (timeDiffP)
import           Text.Printf (printf)

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
            !xe <- timingP "escrow-new" $ PVSS.escrowNew t

            !xcommitments <- timingP "commitments" $ return $ PVSS.createCommitments xe

            !xesharesChunks <- timingP "shares" $ forM (chunk 200 $ zip [1..] (map PVSS.toPublicKey participants)) $ \c ->
                timingP ("  chunk-" ++ show (fst $ head c)) $ forM c $ uncurry (PVSS.shareCreate xe xcommitments)
            let eshares = mconcat xesharesChunks
            return (xe, xcommitments, eshares)


    !validated <- timingP "validating" $ forM (chunk 200 $ zip eshares (map PVSS.toPublicKey participants)) $ \c ->
        timingP ("  vchunk") $ forM c $ return . PVSS.verifyEncryptedShare (PVSS.escrowExtraGen e) commitments
    putStrLn (show $ and $ concat validated)

    !decryptedShares <- timingP "decrypting" $ mapM (\(kp,eshare) -> do
            p <- PVSS.shareDecrypt kp eshare
            return $! p
        ) (zip participants eshares)

    !verifiedShares <- timingP "verifying" $ return $
        PVSS.getValidRecoveryShares t (zip3 eshares (map PVSS.toPublicKey participants) decryptedShares)
    putStrLn (show $ t == fromIntegral (length verifiedShares))

    recovered <- timingP "recovering" $ return $ PVSS.recover $ take (fromIntegral t+1) $ decryptedShares
    putStrLn $ show recovered

goScrape :: SCRAPE.Threshold -> Int -> IO ()
goScrape t n = do
    keypairParticipants <- timingP "keypair" (replicateM n $ PVSS.keyPairGenerate)
    () <- deepseq keypairParticipants (return ())
    let participantsPublicKeys = map PVSS.toPublicKey keypairParticipants
        participants           =  SCRAPE.Participants participantsPublicKeys

    (extraGen, sec, esis, commitments, parallelProofs) <- timingP "escrow" $ SCRAPE.escrow t participants

    !validated <- timingP "validating" $ SCRAPE.verifyEncryptedShares extraGen t commitments parallelProofs esis participants
    putStrLn ("encrypted validated: " ++ show validated)

    !decryptedShares <- timingP "decrypting" $ mapM (\(kp,eshare) -> do
            p <- SCRAPE.shareDecrypt kp eshare
            return $! p
        ) (zip keypairParticipants esis)

    !v <- timingPureP "verifying-decrypted" $
        and $ map (SCRAPE.verifyDecryptedShare) $ zip3 esis participantsPublicKeys decryptedShares
    putStrLn $ show v

    recovered <- timingPureP "recovering" $ SCRAPE.recover $ zip [1..] $ take (fromIntegral t) $ decryptedShares
    putStrLn $ "secret   : " ++ show sec
    putStrLn $ "recovered: " ++ show recovered

main :: IO ()
main = do
    args <- getArgs
    case args of
        ["scrape", tS, nS] -> goScrape (read tS) (read nS)
        [tS, nS]           -> go (read tS) (read nS)
        _                  -> error "error: pvss [scrape] <threshold> <number>"
