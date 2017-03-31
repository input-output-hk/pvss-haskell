{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PVSS.ECC
    ( Point(..)
    , Scalar(..)
    , PublicKey(..)
    , PrivateKey(..)
    , KeyPair(..)
    , DhSecret(..)
    , curveGenerator
    , pointToDhSecret
    , pointFromSecret
    , pointIdentity
    , keyPairGenerate
    , keyGenerate
    , keyFromBytes
    , keyFromNum
    , keyInverse
    , (#+)
    , (#-)
    , (#*)
    , (#^)
    , (.+)
    , (.-)
    , (.*)
    , (*.)
    , mulAndSum
    , mulPowerAndSum
    , hashPoints
    , hashPointsToKey
    ) where

#define OPENSSL

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)
import           Data.Bits
import           Data.Binary
import           Data.Binary.Get (getByteString)
import           Data.Binary.Put (putByteString)

import           GHC.Generics
import           Control.DeepSeq
import           Crypto.Hash (hash, SHA256, Digest)
import           Crypto.Number.Serialize
import           Crypto.Number.ModArithmetic (expFast)
import           Crypto.Random

#ifdef OPENSSL
import qualified Crypto.OpenSSL.ECC as SSL
import GHC.Integer.GMP.Internals (recipModInteger)
import Crypto.Number.Generate
#else
import qualified Crypto.PubKey.ECC.P256 as P256
#endif

data KeyPair = KeyPair
    { toPrivateKey :: PrivateKey
    , toPublicKey  :: PublicKey
    }
    deriving (Show,Eq,Generic)

instance Binary KeyPair where
    put (KeyPair priv pub) = put priv >> put pub
    get = KeyPair <$> get <*> get

instance NFData KeyPair

newtype DhSecret = DhSecret ByteString
    deriving (Show,Eq,NFData,Binary)

keyFromBytes :: ByteString -> Scalar
keyFromBytes = keyFromNum . os2ip'
  where os2ip' :: ByteString -> Integer
        os2ip' = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

-- | Private Key
newtype PrivateKey = PrivateKey Scalar
    deriving (Show,Eq,NFData,Binary)

-- | Public Key
newtype PublicKey = PublicKey Point
    deriving (Show,Eq,NFData,Binary)

#ifdef OPENSSL

p256 :: SSL.EcGroup
p256 = maybe (error "p256 curve") id $ SSL.ecGroupFromCurveOID "1.2.840.10045.3.1.7"

newtype Point = Point { unPoint :: SSL.EcPoint }
    deriving (Generic)

instance NFData Point where
    rnf (Point p) = p `seq` ()

instance Show Point where
    show (Point p) =
        let (x,y) = SSL.ecPointToAffineGFp p256 p
         in ("Point " ++ show x ++ " " ++ show y)
instance Eq Point where
    (Point a) == (Point b) = SSL.ecPointEq p256 a b
instance Binary Point where
    put = putByteString
        . flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed
        . unPoint
    get = either fail (return . Point) . SSL.ecPointFromOct p256 =<< getByteString 33

newtype Scalar = Scalar { unScalar :: Integer }
    deriving (Show,Eq,Generic,NFData)
instance Binary Scalar where
    put (Scalar i) = putByteString $ i2ospOf_ 32 i
    get = keyFromBytes <$> getByteString 32

keyFromNum :: Integer -> Scalar
keyFromNum n = Scalar (n `mod` SSL.ecGroupGetOrder p256)

keyInverse :: Scalar -> Scalar
keyInverse (Scalar 0) = Scalar 0
keyInverse (Scalar a) = Scalar $ recipModInteger a order
  where
    order = SSL.ecGroupGetOrder p256

keyGenerate :: MonadRandom randomly => randomly Scalar
keyGenerate = Scalar <$> generateMax order
  where
    order = SSL.ecGroupGetOrder p256

keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = do
    k <- keyGenerate
    return $ KeyPair (PrivateKey k) (PublicKey $ pointFromSecret k)

pointToDhSecret :: Point -> DhSecret
pointToDhSecret (Point p) =
    let (x, _) = SSL.ecPointToAffineGFp p256 p
     in DhSecret $ B.convert $ hashSHA256 $ i2ospOf_ 32 x

pointFromSecret :: Scalar -> Point
pointFromSecret (Scalar s) = Point $ SSL.ecPointGeneratorMul p256 s

pointIdentity :: Point
pointIdentity = Point $ SSL.ecPointInfinity p256

hashPoints :: [Point] -> ByteString
hashPoints elements =
    B.convert $ hashSHA256 $ mconcat
              $ fmap (flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed . unPoint) elements

hashPointsToKey :: [Point] -> Scalar
hashPointsToKey elements =
    keyFromBytes $ B.convert $ hashSHA256 $ mconcat
                 $ fmap (flip (SSL.ecPointToOct p256) SSL.PointConversion_Compressed . unPoint) elements

curveGenerator :: Point
curveGenerator = Point $ SSL.ecGroupGetGenerator p256

-- | Point adding
(.+) :: Point -> Point -> Point
(.+) (Point a) (Point b) = Point (SSL.ecPointAdd p256 a b)

-- | Point subtraction
(.-) :: Point -> Point -> Point
(.-) (Point a) (Point b) = Point (SSL.ecPointAdd p256 a $ SSL.ecPointInvert p256 b)

-- | Point scaling
(.*) :: Point -> Scalar -> Point
(.*) (Point a) (Scalar s) = Point (SSL.ecPointMul p256 a s)

-- | Point scaling, flip (*.)
(*.) :: Scalar -> Point -> Point
(*.) (Scalar s) (Point a) = Point (SSL.ecPointMul p256 a s)

(#+) :: Scalar -> Scalar -> Scalar
(#+) (Scalar a) (Scalar b) = keyFromNum (a + b)

(#-) :: Scalar -> Scalar -> Scalar
(#-) (Scalar a) (Scalar b) = keyFromNum (a - b)

(#*) :: Scalar -> Scalar -> Scalar
(#*) (Scalar a) (Scalar b) = keyFromNum (a * b)

(#^) :: Scalar -> Integer -> Scalar
(#^) (Scalar a) n =
    Scalar $ expFast a n order
  where
    order = SSL.ecGroupGetOrder p256

mulAndSum :: [(Point,Scalar)] -> Point
mulAndSum l = Point $ SSL.ecPointsMulAndSum p256 (map (\(Point p, Scalar s) -> (p, s)) l)

mulPowerAndSum :: [Point] -> Integer -> Point
mulPowerAndSum l n = Point $ SSL.ecPointsMulOfPowerAndSum p256 (map unPoint l) n

#else
newtype Point = Point { unPoint :: P256.Point }
    deriving (Show,Eq)

newtype Scalar = Scalar P256.Scalar
    deriving (Eq)

instance Show Scalar where
    show (Scalar p) = show (P256.scalarToInteger p)

p256Mod :: Integer
p256Mod = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

curveGenerator :: Point
curveGenerator = pointIdentity

pointFromSecret :: Scalar -> Point
pointFromSecret (Scalar s) = Point $ P256.toPoint s

pointToDhSecret :: Point -> DhSecret
pointToDhSecret (Point p) = DhSecret $ B.convert $ hashSHA256 $ P256.pointToBinary p

-- | Point adding
(.+) :: Point -> Point -> Point
(.+) (Point a) (Point b) = Point (P256.pointAdd a b)

-- | Point scaling
(.*) :: Point -> Scalar -> Point
(.*) (Point a) (Scalar s) = Point (P256.pointMul s a)

-- | Point scaling, flip (*.)
(*.) :: Scalar -> Point -> Point
(*.) (Scalar s) (Point a) = Point (P256.pointMul s a)

(#+) :: Scalar -> Scalar -> Scalar
(#+) (Scalar a) (Scalar b) = Scalar (P256.scalarAdd a b)

(#-) :: Scalar -> Scalar -> Scalar
(#-) (Scalar a) (Scalar b) = Scalar (P256.scalarSub a b)

(#*) :: Scalar -> Scalar -> Scalar
(#*) (Scalar a) (Scalar b) =
    Scalar $ throwCryptoError $ P256.scalarFromInteger ((an * bn) `mod` p256Mod)
  where
    an = P256.scalarToInteger a
    bn = P256.scalarToInteger b

(#^) :: Scalar -> Integer -> Scalar
(#^) (Scalar a) n =
    Scalar $ throwCryptoError
           $ P256.scalarFromInteger
           $ expSafe (P256.scalarToInteger a) n p256Mod

pointIdentity :: Point
pointIdentity = Point $ P256.pointFromIntegers 0 0

keyFromNum :: Integer -> Scalar
keyFromNum = Scalar . throwCryptoError . P256.scalarFromInteger

keyInverse :: Scalar -> Scalar
keyInverse (Scalar s) = Scalar (P256.scalarInv s)

keyGenerate :: MonadRandom randomly => randomly Scalar
keyGenerate = Scalar <$> P256.scalarGenerate

keyPairGenerate :: MonadRandom randomly => randomly KeyPair
keyPairGenerate = do
    k <- keyGenerate
    return $ KeyPair k (pointFromSecret k)

hashPointsToKey :: [Point] -> Scalar
hashPointsToKey elements =
    keyFromBytes $ B.convert $ hashSHA256 $ mconcat $ fmap (P256.pointToBinary . unPoint) elements

#endif

hashSHA256 :: ByteString -> Digest SHA256
hashSHA256 m = hash m
