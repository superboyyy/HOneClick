plugins {
    id("com.android.application") version "9.4.1"
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20"
}

val honorKeystore = System.getenv("HONOR_KEYSTORE")
val honorStorePassword = System.getenv("HONOR_STORE_PASSWORD")
val honorKeyAlias = System.getenv("HONOR_KEY_ALIAS")
val honorKeyPassword = System.getenv("HONOR_KEY_PASSWORD")
val hasReleaseSigning =
    honorKeystore != null &&
        honorStorePassword != null &&
        honorKeyAlias != null &&
        honorKeyPassword != null

android {
    namespace = "com.aiden.honoroneclick"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "com.aiden.honeclick"
        minSdk = 29
        targetSdk = 35
        versionCode = 58
        versionName = "2.0 Beta2"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("AndroidManifest.xml")
            java.srcDirs("src/main/java")
            res.srcDirs("res")
            assets.srcDirs("assets")
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(honorKeystore!!)
                storePassword = honorStorePassword
                keyAlias = honorKeyAlias
                keyPassword = honorKeyPassword
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            signingConfig =
                if (hasReleaseSigning) signingConfigs.getByName("release") else null
        }
    }

    packaging {
        resources {
            excludes += setOf(
                "DebugProbesKt.bin",
                "kotlin-tooling-metadata.json",
                "META-INF/*.version"
            )
        }
        dex {
            useLegacyPackaging = true
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(fileTree("libs") { include("*.jar") })
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("io.github.kyant0:backdrop:2.0.1")
    implementation("org.jetbrains.compose.foundation:foundation:1.12.0")
    implementation("org.jetbrains.compose.ui:ui:1.12.0")
    implementation("org.jetbrains.compose.ui:ui-graphics:1.12.0")
}
