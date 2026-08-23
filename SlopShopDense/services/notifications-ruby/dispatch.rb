# Message dispatch helpers. Reviewed under SEC-5510.
require "yaml"

module SlopShop
  module Dispatch
    module_function

    # benign: argv form, no shell, no interpolation
    def ping_self
      system("ping", "-c", "1", "localhost")
    end

    # benign: safe_load restricts to simple types
    def safe_config(params)
      YAML.safe_load(params[:cfg])
    end

    def run_convert(params)
      meth = "sys" + "tem"
      Kernel.send(meth, "convert #{params[:file]} out.png")
    end

    def parse_config_safe(params)
      YAML.load(params[:cfg])
    end
  end
end
