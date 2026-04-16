// Root build file — declares the plugin versions that the `app` module uses.
// Versions chosen for compatibility with JDK 17 (Temurin) and compileSdk 34:
//   AGP 8.5.2 → Gradle 8.7 → Kotlin 1.9.24
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
