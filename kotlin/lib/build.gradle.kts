import java.io.ByteArrayOutputStream

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "org.world.walletkit"
    compileSdk = 33

    defaultConfig {
        minSdk = 23

        @Suppress("deprecation")
        targetSdk = 33

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    // TODO: Review
    // buildTypes {
    //     getByName("release") {
    //         isMinifyEnabled = false
    //         proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    //     }
    // }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
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

                version = if (project.hasProperty("versionName")) {
                    project.property("versionName") as String
                } else {
                    val stdout = ByteArrayOutputStream()
                    project.exec {
                        commandLine = listOf(
                            "curl", "-s", "-H",
                            "Authorization: token ${System.getenv("GITHUB_TOKEN")}",
                            "https://api.github.com/repos/worldcoin/walletkit/releases/latest"
                        )
                        standardOutput = stdout
                    }
                    val response = stdout.toString()
                    val tag = Regex("\"tag_name\":\\s*\"(.*?)\"")
                        .find(response)?.groupValues?.get(1) ?: "0.0.0"
                    "$tag"
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

dependencies {
    implementation("net.java.dev.jna:jna:5.13.0@aar")
    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.appcompat:appcompat:1.4.1")
    implementation("com.google.android.material:material:1.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
