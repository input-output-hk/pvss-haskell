{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE FlexibleInstances #-}

module Main (main) where

import Foundation
import Foundation.Check (Arbitrary(..))
import qualified Crypto.PVSS as PVSS

import Crypto.Random

import Data.Binary
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.ByteArray (convert, Bytes)

import Inspector
import Inspector.Display
import Inspector.Parser

type PVSSEscrow
    =  "crypto" :> "pvss" :> "escrow"
    :> Payload "threshold"   PVSS.Threshold
    :> Payload "public-keys"  [PVSS.PublicKey]
    :> ( Payload "extra-gen"        PVSS.ExtraGen
       , Payload "secret"           PVSS.Secret
       , Payload "proof"            PVSS.Proof
       , Payload "commitments"      [PVSS.Commitment]
       , Payload "encrypted-shares" [PVSS.EncryptedShare]
       )

main :: IO ()
main = defaultMain $
    group $ do
        summary "PVSS's escrow function"
        golden (Proxy @PVSSEscrow) $ \t keys ->
            let chachadrg = drgNewTest (0,0,0,0,42)
             in fst $ withDRG chachadrg (PVSS.escrow t keys)

-- unfortunate orphan instances

instance Arbitrary PVSS.PublicKey where
    arbitrary = do
        rng <- drgNewTest <$> arbitrary
        pure $ fst $ withDRG rng (PVSS.toPublicKey <$> PVSS.keyPairGenerate)

instance Display PVSS.ExtraGen where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"
instance Display PVSS.Secret where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"
instance Display PVSS.Proof where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"
instance Display PVSS.Commitment where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"
instance Display PVSS.EncryptedShare where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"
instance Display PVSS.PublicKey where
    display  = displayByteArrayAccess . toStrict . encode
    encoding _ = "hexadecimal"

instance HasParser PVSS.ExtraGen where
    getParser = parseBinary
instance HasParser PVSS.Secret where
    getParser = parseBinary
instance HasParser PVSS.Proof where
    getParser = parseBinary
instance HasParser PVSS.Commitment where
    getParser = parseBinary
instance HasParser PVSS.EncryptedShare where
    getParser = parseBinary
instance HasParser PVSS.PublicKey where
    getParser = parseBinary

parseBinary :: Binary a => Parser String a
parseBinary = do
    bs <- fromStrict . convert <$> bytesParser
    case decodeOrFail bs of
        Left (_,_,err) -> reportError $ Expected "" (fromList err)
        Right (_,_,a)  -> pure a
  where
    bytesParser :: Parser String Bytes
    bytesParser = getParser
