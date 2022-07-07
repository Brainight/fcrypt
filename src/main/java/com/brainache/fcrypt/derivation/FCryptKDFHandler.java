/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.brainache.fcrypt.derivation;

/**
 *
 * @author Brainight
 */
public abstract class FCryptKDFHandler implements FCryptHasher, FCryptVerifier{
    
    protected final FCryptKDFunction kdf;

    public FCryptKDFHandler(FCryptKDFunction kdf) {
        this.kdf = kdf;
    }

    public FCryptKDFunction getKdf() {
        return kdf;
    }
    
    
    
    
    
    
    
    
}
