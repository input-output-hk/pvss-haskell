{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.PVSS.DLEQ
    ( DLEQ(..)
    , Proof(..)
    , generate
    , verify
    ) where

import GHC.Generics
import Control.DeepSeq
import Crypto.PVSS.ECC
import Data.ByteString (ByteString)
import           Data.Binary
import           Data.Binary.Get (getByteString)
import           Data.Binary.Put (putByteString)

data DLEQ = DLEQ
    { dleq_g1 :: !Point -- ^ g1 parameter
    , dleq_h1 :: !Point -- ^ h1 parameter where h1 = g1^a
    , dleq_g2 :: !Point -- ^ g2 parameter
    , dleq_h2 :: !Point -- ^ h2 parameter where h2 = g2^a
    } deriving (Show,Eq,Generic)

instance NFData DLEQ

newtype Challenge = Challenge ByteString
    deriving (Show,Eq,NFData)
instance Binary Challenge where
    put (Challenge c) = put c
    get = Challenge <$> getByteString 32

-- | The generated proof
data Proof = Proof
    { proof_c  :: !Challenge
    , proof_z  :: !Scalar
    } deriving (Show,Eq,Generic)

instance Binary Proof
instance NFData Proof

-- | Generate a proof
generate :: Scalar -- ^ random value
         -> Scalar -- ^ a
         -> DLEQ   -- ^ DLEQ parameters to generate from
         -> Proof
generate w a pp@(DLEQ g1 h1 g2 h2) = Proof (Challenge c) r
  where
    a1     = g1 .* w
    a2     = g2 .* w
    c      = hashPoints [h1,h2,a1,a2]
    r      = w #+ (a #* keyFromBytes c)

-- | Verify a proof
verify :: DLEQ  -- ^ DLEQ parameter used to verify
       -> Proof -- ^ the proof to verify
       -> Bool
verify (DLEQ g1 h1 g2 h2) (Proof (Challenge ch) r) = ch == hashPoints [h1,h2,a1,a2]
  where
    r1 = g1 .* r
    r2 = g2 .* r
    c = keyFromBytes ch
    a1 = r1 .- (h1 .* c)
    a2 = r2 .- (h2 .* c)
