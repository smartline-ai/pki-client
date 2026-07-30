// Package pkiclient приводит участника флота — ноду, сервис или клиента — к
// состоянию, в котором у него есть рабочая mTLS-идентичность: генерирует
// ключ, присоединяется к Control Plane по одноразовому токену и обновляет
// сертификат, пока процесс жив.
//
// Лифтинг из executor-node/internal/bootstrap (план 03, задача 1). Пакет уже
// реализовывал весь жизненный цикл сертификата — атомарную запись,
// инспекцию состояния (CertValid/CertAbsent/CertExpiring/CertUnreadable),
// join по CSR, проверку, что выданный лист совпадает с тем ключом, на
// который он подписан, обновление на трети оставшегося срока и горячую
// замену без рестарта через CertSource — и не подлежал переписыванию.
// Node-специфичным он был ровно в двух местах: Deps нёс executor-овский
// *config.Config целиком, а joinRequest жёстко называл
// node_id/addresses/capacity. Оба места стали явными и kind-agnostic
// (Identity{Kind, CN, IP} и Extra map[string]any), остальной код не менялся.
package pkiclient

import "net"

// Kind — вид участника, которому Control Plane выдаёт удостоверение. Три
// значения соответствуют тому, что теперь принимает generalised-ручка
// POST /v1/principals/join (план 02, задача 2 control-plane): kind
// определяет, что вправе требовать предъявитель, вместе с политикой,
// закреплённой за join-токеном на стороне CP.
type Kind string

const (
	// KindNode — исполнитель. Серверный + клиентский лист, SAN — один адрес
	// в RFC1918, рождающийся на Volume самой ноды.
	KindNode Kind = "node"
	// KindService — демон, который слушает, но нодой не является (например
	// builder). SAN — адрес, прижатый в токене при выпуске.
	KindService Kind = "service"
	// KindClient — сторона, которая только ходит. Лист без SAN IP и только
	// с clientAuth: сертификат, которым нельзя представиться сервером.
	KindClient Kind = "client"
)

// Identity — то, что уходит в CSR. CN есть всегда; IP заполняется только для
// видов с сетевым адресом (node, service) и остаётся nil для client — что и
// заставляет buildCSR не добавлять SAN IP в шаблон, как того требует
// control-plane/internal/pki.ValidateCSR для клиентского листа.
type Identity struct {
	Kind Kind
	CN   string
	IP   net.IP
}
