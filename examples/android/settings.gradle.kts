pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/worldcoin/walletkit")
            credentials {
                username = "lukejmann"
                password = "..."
            }
            metadataSources {
                gradleMetadata()
                artifact()
            }
        }
    }
}

rootProject.name = "walletkit-sample"
include(":app")
