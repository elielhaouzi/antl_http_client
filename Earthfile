VERSION 0.5

elixir-base:
    FROM elixir:1.12.2-alpine
    WORKDIR /app
    RUN apk add --no-progress --update openssh-client git build-base mysql-client
    RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan gitlab.annatel.net >> ~/.ssh/known_hosts
    RUN mix local.rebar --force && mix local.hex --force

deps:
    ARG MIX_ENV
    FROM +elixir-base
    ENV MIX_ENV="$MIX_ENV"
    COPY mix.exs .
    COPY mix.lock .
    RUN mix deps.get --only "$MIX_ENV"
    RUN mix deps.compile

    
test:
    FROM --build-arg MIX_ENV="test" +deps
    COPY --dir config lib test .
    RUN mix test

lint:
    FROM --build-arg MIX_ENV="test" +deps
    COPY .formatter.exs .
    RUN mix deps.unlock --check-unused
    RUN mix format --check-formatted
    RUN mix compile --warnings-as-errors

check-tag:
    ARG TAG
    FROM +elixir-base
    COPY mix.exs .
    COPY --dir config .
    ARG APP_VERSION=$(mix app.version)
    IF [ ! -z $TAG ] && [ ! $TAG == $APP_VERSION ]
        RUN echo "TAG '$TAG' has to be equal to APP_VERSION '$APP_VERSION'" && false
    END
