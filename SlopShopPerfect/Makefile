SERVICES := storefront identity catalog orders payments search media generation admin

.PHONY: deps lint build clean

deps:
	cd services/storefront && npm ci
	cd services/identity && python -m pip install --require-hashes -r requirements.txt
	cd services/generation && python -m pip install --require-hashes -r requirements.txt
	cd services/catalog && go mod download
	cd services/search && cargo fetch --locked
	cd services/orders && mvn --batch-mode dependency:go-offline
	cd services/admin && composer install --no-interaction
	cd ops && bundle install

lint:
	cd services/storefront && npm run lint
	cd services/identity && ruff check .
	cd services/generation && ruff check .
	cd services/catalog && go vet ./...
	cd services/search && cargo clippy --locked
	cd services/orders && mvn --batch-mode verify -DskipTests
	cd services/admin && composer run-script lint
	cd ops && bundle exec rubocop
	shellcheck ops/bin/*.sh

build:
	cd services/storefront && npm run build
	cd services/catalog && go build ./...
	cd services/search && cargo build --release --locked
	cd services/orders && mvn --batch-mode package
	cd services/payments && dotnet build --configuration Release
	cmake -S services/media -B services/media/build && cmake --build services/media/build

clean:
	rm -rf services/*/dist services/*/target services/*/build services/*/bin
