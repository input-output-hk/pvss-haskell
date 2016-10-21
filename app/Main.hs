{-# LANGUAGE BangPatterns #-}
module Main where

import           System.Environment
import           Control.Monad
import           Control.DeepSeq
import           Crypto.Random
import qualified Crypto.PVSS as PVSS
import           Data.Hourglass
import           Time.Types
import           Time.System

timing f = do
    t1 <- timeCurrentP
    a  <- f
    t2 <- a `deepseq` timeCurrentP
    return (a, t2 `timeDiffP` t1)

timingP n f = do
    (a, t) <- timing f
    putStrLn (n ++ ": " ++ show t)
    return a

chunk _ [] = []
chunk n l =
    let (l1,l2) = splitAt n l
     in l1 : chunk n l2

go t n = do
    participants <- replicateM n $ PVSS.keyPairGenerate

    !e <- timingP "escrow-new" $ PVSS.escrowNew t

    !commitments <- timingP "commitments" $ return $ PVSS.createCommitments e

    !esharesChunks <- timingP "shares" $ forM (chunk 200 $ zip [1..] (map PVSS.toPublicKey participants)) $ \c ->
        timingP ("chunk-" ++ show (fst $ head c)) $ forM c $ uncurry (PVSS.shareCreate e commitments)
    let eshares = mconcat esharesChunks


    validated <- timingP "validating" $ forM (chunk 200 $ zip eshares (map PVSS.toPublicKey participants)) $ \c ->
        timingP ("vchunk") $ forM c $ return . PVSS.verifyEncryptedShare (PVSS.escrowExtraGen e) commitments

    !decryptedShares <- timingP "decrypting" $ mapM (\(kp,eshare) -> do
            p <- PVSS.shareDecrypt kp eshare
            return $! p
        ) (zip participants eshares)

    !verifiedShares <- timingP "verifying" $ return $
        PVSS.getValidRecoveryShares t (zip3 eshares (map PVSS.toPublicKey participants) decryptedShares)

    recovered <- timingP "recovering" $ return $ PVSS.recover $ take (fromIntegral t+1) $ decryptedShares
    putStrLn $ show recovered

main :: IO ()
main = do
    args <- getArgs
    case args of
        [tS, nS] -> go (read tS) (read nS)
        _        -> error "error: pvss <threshold> <number>"
