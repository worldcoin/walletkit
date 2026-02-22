import groovy.json.JsonSlurper
import java.io.ByteArrayOutputStream

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.world.walletkit"
    compileSdk = 33

    defaultConfig {
        minSdk = 23
        @Suppress("deprecation")
        targetSdk = 33
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {
                groupId = "org.world"
                artifactId = "walletkit"

                // Read version from Cargo.toml (allow override via -PversionName)
                version = if (project.hasProperty("versionName")) {
                    project.property("versionName") as String
                } else {
                    val cargoToml = file("../../Cargo.toml")
                    val versionRegex = """version\s*=\s*"([^"]+)"""".toRegex()
                    val cargoContent = cargoToml.readText()
                    versionRegex.find(cargoContent)?.groupValues?.get(1)
                        ?: throw GradleException("Could not find version in Cargo.toml")
                }

                afterEvaluate {
                    from(components["release"])
                }
            }
        }

        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/worldcoin/walletkit")
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

// Locate the local maven repo bundled inside rustls-platform-verifier-android.
// https://github.com/rustls/rustls-platform-verifier#android
fun findRustlsPlatformVerifierMaven(): String {
    val out = ByteArrayOutputStream()
    exec {
        workingDir = file("../../")
        commandLine(
            "cargo", "metadata", "--format-version", "1",
            "--filter-platform", "aarch64-linux-android",
        )
        standardOutput = out
    }
    @Suppress("UNCHECKED_CAST")
    val meta = JsonSlurper().parseText(out.toString()) as Map<String, Any>
    @Suppress("UNCHECKED_CAST")
    val packages = meta["packages"] as List<Map<String, Any>>
    val manifest = packages.first { it["name"] == "rustls-platform-verifier-android" }["manifest_path"] as String
    return File(File(manifest).parent, "maven").path
}

repositories {
    maven {
        url = uri(findRustlsPlatformVerifierMaven())
        metadataSources.artifact()
    }
}

dependencies {
    // UniFFI requires JNA for native calls (AAR to avoid jar+aar duplicates)
    implementation("net.java.dev.jna:jna:5.13.0@aar")
    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.appcompat:appcompat:1.4.1")
    implementation("com.google.android.material:material:1.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    // Kotlin helper classes for rustls-platform-verifier (Android cert verification)
    implementation("rustls:rustls-platform-verifier:latest.release")
}
