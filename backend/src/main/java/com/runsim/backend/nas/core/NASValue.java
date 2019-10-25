package com.runsim.backend.nas.core;

public abstract class NASValue {

    public abstract void encode(BitOutputStream stream);

    public abstract void decode(BitInputStream stream);

    public abstract String display();
}
