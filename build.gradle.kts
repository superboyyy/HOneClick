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
        versionCode = 64
        versionName = "2.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    flavorDimensions += "manager"
    productFlavors {
        create("kernelsu") {
            dimension = "manager"
            buildConfigField("String", "ROOT_MANAGER_PACKAGE", "\"me.weishu.kernelsu\"")
            buildConfigField("long", "ROOT_MANAGER_VERSION_CODE", "32680L")
            buildConfigField("String", "ROOT_MANAGER_CERT_SHA256",
                "\"c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6\"")
            buildConfigField("String", "ROOT_MANAGER_ASSET_NAME", "\"KernelSUManager.apk\"")
            buildConfigField("String", "ROOT_MANAGER_ASSET_SHA256",
                "\"b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450\"")
            buildConfigField("String", "ROOT_MANAGER_NAME", "\"KernelSU\"")
            buildConfigField("String", "ROOT_MANAGER_LKM_ASSET", "\"ksu-template-117.ko\"")
            buildConfigField("String", "ROOT_MANAGER_SYMS_ASSET", "\"ko_syms-117.txt\"")
            applicationIdSuffix = ".kernelsu"
            versionNameSuffix = "-KernelSU"
            manifestPlaceholders["appName"] = "HOneClick KernelSU"
        }
        create("sukisu") {
            dimension = "manager"
            buildConfigField("String", "ROOT_MANAGER_PACKAGE", "\"com.sukisu.ultra\"")
            buildConfigField("long", "ROOT_MANAGER_VERSION_CODE", "41150L")
            buildConfigField("String", "ROOT_MANAGER_CERT_SHA256",
                "\"947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef\"")
            buildConfigField("String", "ROOT_MANAGER_ASSET_NAME", "\"SukiSUManager.apk\"")
            buildConfigField("String", "ROOT_MANAGER_ASSET_SHA256",
                "\"6fe64e7bcf9fd768c58f46afea2f27ee9fb85d2783472a7e81334df21e700636\"")
            buildConfigField("String", "ROOT_MANAGER_NAME", "\"SukiSU\"")
            buildConfigField("String", "ROOT_MANAGER_LKM_ASSET", "\"sukisu-template-117.ko\"")
            buildConfigField("String", "ROOT_MANAGER_SYMS_ASSET", "\"ko_syms-sukisu117.txt\"")
            applicationIdSuffix = ".uipreview"
            versionNameSuffix = "-ui"
            manifestPlaceholders["appName"] = "HOneClick UI"
        }
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
