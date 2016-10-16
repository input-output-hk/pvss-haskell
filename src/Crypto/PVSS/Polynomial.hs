{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PVSS.Polynomial
    ( Polynomial(..)
    , generate
    , evaluate
    , atZero
    ) where

import Crypto.PVSS.ECC
import Crypto.Random
import Control.Monad
import Control.DeepSeq
import Data.List

-- | a group of coefficient starting from the
-- smallest degree.
newtype Polynomial = Polynomial [Scalar]
    deriving (Show,Eq,NFData)

generate :: MonadRandom randomly => Int -> randomly Polynomial
generate i
    | i <= 0    = error ("invalid polynomial degree: " ++ show i)
    | otherwise = Polynomial <$> replicateM i keyGenerate

evaluate :: Polynomial -> Scalar -> Scalar
evaluate (Polynomial a) v =
    foldl' (#+) (keyFromNum 0) $ zipWith (#*) a es
  where
    es = [ (v #^ degree) | degree <- [0..] ]

atZero :: Polynomial -> Scalar
atZero (Polynomial coeffs) = coeffs !! 0
