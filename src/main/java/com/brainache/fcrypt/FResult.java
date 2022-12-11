package com.brainache.fcrypt;

/**
 *
 * @author Brainight
 */
public class FResult<T> {
    
    private final T target;
    private final boolean valid;
    private final String msg;
    
    public FResult(T target, boolean isValid, String msg){
        this.target = target;
        this.valid = isValid;
        this.msg = msg;
    }

    public T getTarget() {
        return target;
    }

    public boolean isValid() {
        return valid;
    }

    public String getMsg() {
        return msg;
    }
    
}
