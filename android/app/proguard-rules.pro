# Keep kotlinx.serialization generated serializers
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.jamesbaird.cryptojack.data.** {
    *** Companion;
}
-keepclasseswithmembers class com.jamesbaird.cryptojack.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}
