// This build.gradle uses a JVM-only testing engine for unit testing.
// Note this is separate from the build.gradle used for building and publishing the actual library.

plugins {
    kotlin("jvm") version "1.9.22"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.13.0")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

sourceSets {
    test {
        kotlin.srcDirs(
            "$rootDir/walletkit-android/src/main/java/uniffi/walletkit_core"
        )
    }
}

tasks.test {
    useJUnit()
    systemProperty("jna.library.path", "${rootDir}/libs")
    reports.html.required.set(false)
}
