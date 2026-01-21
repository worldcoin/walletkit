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
                artifactId = "walletkit-android"

                // Read version from Cargo.toml
                val cargoToml = file("../../Cargo.toml")
                val versionRegex = """version\s*=\s*"([^"]+)"""".toRegex()
                val cargoContent = cargoToml.readText()
                version = versionRegex.find(cargoContent)?.groupValues?.get(1)
                    ?: throw GradleException("Could not find version in Cargo.toml")

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

dependencies {
    // UniFFI requires JNA for native calls
    implementation("net.java.dev.jna:jna:5.13.0")
    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.appcompat:appcompat:1.4.1")
    implementation("com.google.android.material:material:1.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
