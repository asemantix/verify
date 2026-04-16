package app.authentixsign

import android.content.Context
import java.io.File

/**
 * Source de τ — compteur monotone local (Revendication R10).
 *
 * Triple-ancrage pour résister à l'effacement sélectif :
 *   A1  SharedPreferences "authentix_counter_1"
 *   A2  SharedPreferences "authentix_counter_2"
 *   A3  File filesDir/.counter_seal
 *
 * Au démarrage, τ = MAX(A1, A2, A3) — une corruption partielle ne peut jamais
 * faire reculer le compteur. À chaque next(), τ est incrémenté et écrit
 * synchroniquement dans les trois ancrages avec commit().
 *
 * INTERDIT : System.currentTimeMillis() — horloge système manipulable.
 */
object MonotonicCounter {

    private const val PREFS_1 = "authentix_counter_1"
    private const val PREFS_2 = "authentix_counter_2"
    private const val FILE_NAME = ".counter_seal"
    private const val KEY      = "tau"

    /**
     * Incrémente τ de façon monotone et persiste dans les trois ancrages.
     * Retourne la nouvelle valeur.
     */
    @Synchronized
    fun next(context: Context): Long {
        val current = read(context)
        val next = current + 1L
        writeAll(context, next)
        return next
    }

    /**
     * Lit τ sans l'incrémenter (MAX des trois ancrages).
     */
    fun peek(context: Context): Long = read(context)

    /**
     * Vérifie la monotonie stricte.
     */
    fun isMonotonicallyAfter(tauNew: Long, tauOld: Long): Boolean = tauNew > tauOld

    // ── Implémentation ────────────────────────────────────────────────────────

    private fun read(context: Context): Long {
        val a1 = context.getSharedPreferences(PREFS_1, Context.MODE_PRIVATE)
            .getLong(KEY, 0L)
        val a2 = context.getSharedPreferences(PREFS_2, Context.MODE_PRIVATE)
            .getLong(KEY, 0L)
        val a3 = runCatching {
            val f = File(context.filesDir, FILE_NAME)
            if (f.exists()) f.readText().trim().toLongOrNull() ?: 0L else 0L
        }.getOrDefault(0L)
        return maxOf(a1, a2, a3)
    }

    private fun writeAll(context: Context, tau: Long) {
        context.getSharedPreferences(PREFS_1, Context.MODE_PRIVATE)
            .edit().putLong(KEY, tau).commit()
        context.getSharedPreferences(PREFS_2, Context.MODE_PRIVATE)
            .edit().putLong(KEY, tau).commit()
        runCatching {
            File(context.filesDir, FILE_NAME).writeText(tau.toString())
        }
    }
}
