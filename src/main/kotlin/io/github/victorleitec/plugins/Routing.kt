package io.github.victorleitec.plugins

import io.github.victorleitec.authenticate
import io.github.victorleitec.data.user.UserDataSource
import io.github.victorleitec.getSecretInfo
import io.github.victorleitec.security.hashing.HashingService
import io.github.victorleitec.security.token.TokenConfig
import io.github.victorleitec.security.token.TokenService
import io.github.victorleitec.signIn
import io.github.victorleitec.signUp
import io.ktor.server.routing.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.request.*

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    routing {
        signIn(userDataSource, hashingService, tokenService, tokenConfig)
        signUp(hashingService, userDataSource)
        authenticate()
        getSecretInfo()
    }
}
