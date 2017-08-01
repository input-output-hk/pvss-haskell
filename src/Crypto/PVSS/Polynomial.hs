{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.PVSS.Polynomial
    ( Polynomial(..)
    , Degree(..)
    , generate
    , evaluate
    , atZero
    , lambda
    ) where

import Crypto.PVSS.ECC
import Crypto.Random
import Control.Monad
import Control.DeepSeq
import Foundation.Array
import Foundation.Collection ((!), length, foldl')
import Foundation (Offset(..), CountOf(..))
import qualified Foundation as F ((+))
import Prelude hiding (length)

-- | a group of coefficient starting from the
-- smallest degree.
newtype Polynomial = Polynomial [Scalar]
    deriving (Show,Eq,NFData)

-- | Degree of a polynomial
--
-- Degree 0 : constant : P(x) = C
-- Degree 1 : linear   : P(x) = C0 + C1 * x
-- ..
-- Degree n :          : P(x) = C0 + C1 * x + ... + Cn * x^n
newtype Degree = Degree Int
    deriving (Show,Eq,NFData)

-- | Generate a polynomial of the specified degree n
--
-- a0 + a1 * x + a2 * x^2 + ... + an-1 * x^n-1
generate :: MonadRandom randomly => Degree -> randomly Polynomial
generate (Degree i)
    | i < 0     = error ("invalid polynomial degree: " ++ show i)
    | otherwise = Polynomial <$> replicateM (i+1) keyGenerate

evaluate :: Polynomial -> Scalar -> Scalar
evaluate (Polynomial a) v =
    foldl' (#+) (keyFromNum 0) $ zipWith (#*) a es
  where
    es = [ (v #^ degree) | degree <- [0..] ]

atZero :: Polynomial -> Scalar
atZero (Polynomial coeffs) = coeffs !! 0

-- | Lambda polynomial value for lagrange interpolation
--
-- Lambda(i) = Product ( s(j) / (s(j) - s(i)) )
--
lambda :: Array Scalar -> Offset Scalar -> Scalar
lambda xs i = factor (Offset 0) (keyFromNum 1)
  where
    !xi = xs !!! i
    !(CountOf len) = length xs
    factor !j !acc
        | j == Offset len = acc
        | j == i          = factor (j F.+ Offset 1) acc
        | otherwise  =
            let xj = xs !!! j
                e  = xj #* keyInverse (xj #- xi)
             in factor (j F.+ Offset 1) (acc #* e)
    (!!!) arr idx = maybe (error $ "out of bound: " ++ show idx ++ " " ++ show i) id (arr ! idx)
