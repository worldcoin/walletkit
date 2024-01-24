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
            url = uri("https://maven.pkg.github.com/worldcoin/wallet-kit")
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

rootProject.name = "wallet-kit-sample"
include(":app")
