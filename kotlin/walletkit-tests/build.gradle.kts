// This build.gradle uses a JVM-only testing engine for unit testing.
// Note this is separate from the build.gradle used for building and publishing the actual library.

plugins {
    kotlin("jvm")
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

sourceSets {
    test {
        kotlin.srcDirs(
            "$rootDir/walletkit/src/main/java/org/world/walletkit"
        )
    }
}

tasks.test {
    useJUnit()
    systemProperty("java.library.path", "${rootDir}/libs")
    reports.html.required.set(false)
}
