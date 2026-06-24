// Android library module for device-seal. This configuration has been built: `./gradlew assembleRelease`
// resolves these dependencies and compiles all sources into an AAR, verified with the committed Gradle 8.9
// wrapper, AGP 8.7.0, and Kotlin 2.0.21 against a local SDK (compileSdk 35). Newer toolchains should work but
// AGP↔Gradle versions must stay compatible (the wrapper pins Gradle 8.9 so the AGP 8.7.0 pin below matches).
plugins {
    id("com.android.library") version "8.7.0"
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

android {
    namespace = "tools.thinking.deviceseal"
    compileSdk = 35

    defaultConfig {
        // minSdk 30 (Android 11): the clean per-use/auth-type API setUserAuthenticationParameters(int, int)
        // and crypto-bound DEVICE_CREDENTIAL both require API 30. StrongBox (API 28) and HMAC keys work below
        // this, but standardising on 30 avoids per-API branching in this draft.
        minSdk = 30
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // setAllowedAuthenticators(...) and BiometricManager.Authenticators.* require androidx.biometric >= 1.1.0.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
