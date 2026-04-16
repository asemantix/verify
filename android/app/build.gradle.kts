import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.authentixsign"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.authentixsign"
        minSdk = 21               // matches NDK API level in authentix-core/.cargo/config.toml
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        // Only ship the ABI we actually built. Add armeabi-v7a / x86_64 here
        // once we cross-compile those targets.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // Release signing — credentials live in local.properties (gitignored).
    // The keystore path in RELEASE_STORE_FILE is resolved relative to the
    // project root (authentix-sign/), matching where keytool wrote it.
    signingConfigs {
        create("release") {
            val props = Properties().apply {
                rootProject.file("local.properties").inputStream().use { load(it) }
            }
            storeFile = rootProject.file(props["RELEASE_STORE_FILE"] as String)
            storePassword = props["RELEASE_STORE_PASSWORD"] as String
            keyAlias = props["RELEASE_KEY_ALIAS"] as String
            keyPassword = props["RELEASE_KEY_PASSWORD"] as String
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Keep our libauthentix_core.so out of any legacy "merged native libs"
    // pipeline — AGP's default jniLibs/ → lib/<abi>/ is exactly what we want.
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.0")
    implementation("androidx.fragment:fragment-ktx:1.8.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
