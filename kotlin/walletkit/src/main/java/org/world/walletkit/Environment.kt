package org.world.walletkit

fun Environment.pohRecoveryAgentAddress(): String = NativeBridge.environmentPohRecoveryAgentAddress(ordinal)

fun Environment.worldIdVerifierAddress(): String = NativeBridge.environmentWorldIdVerifierAddress(ordinal)
